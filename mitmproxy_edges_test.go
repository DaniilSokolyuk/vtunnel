package vtunnel

// Paths the behaviour-driven tests never reach — error branches, and the
// interface obligations that only matter when something else calls them.

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// The upstream connection established during the client's handshake is handed to
// the first request only. When the upstream closes it — which any response
// carrying Connection: close does — the next request has to dial a fresh one
// with the same settings, rather than failing the session.
func TestUpstreamTLSConnRedialsAfterUpstreamCloses(t *testing.T) {
	var requests atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		// Every response ends its connection, so the transport cannot reuse one.
		w.Header().Set("Connection", "close")
		fmt.Fprintf(w, "response %d", n)
	}))
	upstream.StartTLS()
	defer upstream.Close()

	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())

	proxy, proxyAddr, ca := startCoverageProxy(t, func(p *MITMProxy) {
		p.SetTransportTLSConfig(&tls.Config{RootCAs: roots})
	})
	proxy.ForwardTo("redial.test:443", "tls://"+upstream.Listener.Addr().String())

	// Keep-alives left on, so both requests share one CONNECT tunnel and
	// therefore one pre-established upstream — which only the first can claim.
	client := coverageClient(proxyAddr, ca, false)
	for i := 1; i <= 2; i++ {
		body := getBody(t, client, "https://redial.test/")
		if want := fmt.Sprintf("response %d", i); body != want {
			t.Fatalf("request %d returned %q, want %q", i, body, want)
		}
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("upstream saw %d requests, want 2", got)
	}
}

// An upgrade whose upstream cannot be reached must produce a status the client
// can read, not a half-open connection: nothing is hijacked until the upstream
// has answered.
func TestUpgradeToUnreachableUpstreamReturnsStatus(t *testing.T) {
	proxy, proxyAddr, ca := startCoverageProxy(t, nil)
	// Port 1 on loopback: reliably nothing listening.
	proxy.ForwardTo("dead.test:443", "127.0.0.1:1")

	req, err := http.NewRequest(http.MethodGet, "https://dead.test/socket", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	resp, err := coverageClient(proxyAddr, ca, true).Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

// An upstream that accepts the connection and then vanishes before answering is
// the ordinary way a handshake fails in production — a restart, a load balancer
// dropping the backend. The client has to get a status out of it, because the
// upstream reply is read before anything is hijacked.
func TestUpgradeToSilentUpstreamReturnsStatus(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close() // accepted, then gone
		}
	}()

	proxy, proxyAddr, ca := startCoverageProxy(t, nil)
	proxy.ForwardTo("silent.test:443", ln.Addr().String())

	req, err := http.NewRequest(http.MethodGet, "https://silent.test/socket", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	resp, err := coverageClient(proxyAddr, ca, true).Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

// A CONNECT to a routed domain whose target is unreachable has to fail the same
// way, before the tunnel is accepted.
func TestConnectToUnreachableTargetReturnsStatus(t *testing.T) {
	proxy, proxyAddr, _ := startCoverageProxy(t, nil)
	proxy.Forward("dead.test") // no CA path: piped, and the pipe cannot be built

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// 127.0.0.1:1 is what a Forward route resolves to only if asked for; ask for
	// it directly so the dial is the thing that fails.
	fmt.Fprint(conn, "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

// Cleartext that is neither TLS nor an HTTP/2 preface arrives on an intercepting
// route as a raw pipe — there is nothing to parse and nothing to inject into. If
// the target cannot be dialled the tunnel simply ends, and the client has to see
// that rather than wait forever: the CONNECT was already answered, so no status
// can be sent any more.
func TestCleartextOnInterceptingRouteWithDeadTargetClosesTunnel(t *testing.T) {
	proxy, proxyAddr, _ := startCoverageProxy(t, nil)
	proxy.ForwardTo("cleartext.test:443", "127.0.0.1:1")

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	fmt.Fprint(conn, "CONNECT cleartext.test:443 HTTP/1.1\r\nHost: cleartext.test:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	// Neither a TLS record nor an HTTP/2 preface, so the raw-pipe branch. It has
	// to be at least as long as the preface the proxy peeks for, or the peek
	// blocks waiting for bytes that are never coming and the tunnel is torn down
	// by the peek timeout instead of by the failed dial — which would make this
	// test pass for the wrong reason.
	opening := []byte("PLAIN /nonsense-long-enough-not-to-block-the-peek\r\n\r\n")
	if len(opening) < len(http2.ClientPreface) {
		t.Fatalf("test fixture is shorter than the %d-byte preface", len(http2.ClientPreface))
	}
	if _, err := conn.Write(opening); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Well inside the proxy's own peek timeout, so a pass here means the dial
	// failure closed the tunnel rather than the clock doing it.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("the tunnel stayed open although its target could not be dialled")
	}
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Fatalf("the read hit its own deadline after %v instead of the tunnel closing", elapsed)
	}
}

// hostFromAuthority feeds the certificate cache when a client sends no SNI, so
// the shapes an authority can take are worth pinning down — an IPv6 literal
// keeps its brackets everywhere else and must lose them here.
func TestHostFromAuthority(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{in: "example.test:443", want: "example.test"},
		{in: "example.test", want: "example.test"},
		{in: "[::1]:443", want: "::1"},
		{in: "[::1]", want: "::1"},
		{in: "", want: ""},
	} {
		if got := hostFromAuthority(tc.in); got != tc.want {
			t.Errorf("hostFromAuthority(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The learned exclusions are keyed by whatever authority a client asked for, so
// the map is bounded and swept. Configured exceptions carry no expiry and have
// to survive a sweep that removes everything else.
func TestNoMITMSweepDropsOnlyExpiredEntries(t *testing.T) {
	p := NewMITMProxy()
	p.MITMExceptions("permanent.test")

	now := time.Now()
	p.noMITMMu.Lock()
	p.noMITM["expired.test:443"] = now.Add(-time.Minute)
	p.noMITM["fresh.test:443"] = now.Add(time.Hour)
	p.sweepNoMITMLocked(now)
	_, expired := p.noMITM["expired.test:443"]
	_, fresh := p.noMITM["fresh.test:443"]
	// Stored as it was written: an exception without a port covers every port,
	// the way a route without one does.
	_, permanent := p.noMITM["permanent.test"]
	p.noMITMMu.Unlock()

	if expired {
		t.Error("an expired exclusion survived the sweep")
	}
	if !fresh {
		t.Error("an exclusion that has not expired was swept away")
	}
	if !permanent {
		t.Error("a configured exception was swept away; only learned ones expire")
	}
}

// closed() is what stops a CONNECT from opening a connection the shutdown can no
// longer reach. A proxy that was never started has a nil channel, and reading it
// must report "open" rather than blocking.
func TestClosedReportsLifecycle(t *testing.T) {
	p := NewMITMProxy()
	if p.closed() {
		t.Fatal("an unstarted proxy reports itself closed")
	}

	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if p.closed() {
		t.Fatal("a running proxy reports itself closed")
	}

	p.Close()
	if !p.closed() {
		t.Fatal("a closed proxy does not report itself closed")
	}
}

// h2StreamConn presents an HTTP/2 stream as a net.Conn so tls.Server can run a
// handshake over it. The address and combined-deadline methods exist to satisfy
// that interface; they are checked here so the shape stays honest rather than
// silently drifting into something that would panic if it were ever called.
func TestH2StreamConnSatisfiesNetConn(t *testing.T) {
	var c net.Conn = newH2StreamConn(io.NopCloser(strings.NewReader("")), httptest.NewRecorder())

	if got := c.LocalAddr().Network(); got != "h2" {
		t.Errorf("LocalAddr().Network() = %q, want h2", got)
	}
	if got := c.RemoteAddr().String(); got != "h2-stream" {
		t.Errorf("RemoteAddr().String() = %q, want h2-stream", got)
	}
	// An httptest recorder supports no deadlines, so this reports the failure
	// rather than pretending: the point is that it returns instead of panicking.
	if err := c.SetDeadline(time.Now().Add(time.Second)); err == nil {
		t.Log("SetDeadline succeeded on a recorder")
	}
}
