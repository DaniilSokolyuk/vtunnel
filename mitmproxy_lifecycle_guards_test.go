package vtunnel

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A peer that opens a connection and never finishes a request holds a goroutine
// and an fd for the life of the process, since Go's default is no limit — the
// same hazard peekTimeout and mitmHandshakeTimeout close one layer further in.
// ReadHeaderTimeout is what bounds it.
//
// The other three must stay unset, and that is the point of asserting it. Read
// and write timeouts would cut off a slow body, a streaming response or an
// upstream that took its time answering. IdleTimeout is armed by net/http only
// on a well-behaved keep-alive connection waiting for its next request, so it
// bounds nothing ReadHeaderTimeout misses and costs a GOAWAY on every quiet
// gRPC channel. When a connection between two healthy endpoints ends is not
// this hop's call.
func TestProxyServerBoundsOnlyTheRequestHeader(t *testing.T) {
	p := NewMITMProxy()
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	_, srv := p.lifecycle()
	if srv.ReadHeaderTimeout == 0 {
		t.Error("outer server has no ReadHeaderTimeout, so a peer that connects and dawdles is unbounded")
	}
	for _, unwanted := range []struct {
		name  string
		value time.Duration
	}{
		{"IdleTimeout", srv.IdleTimeout},
		{"ReadTimeout", srv.ReadTimeout},
		{"WriteTimeout", srv.WriteTimeout},
	} {
		if unwanted.value != 0 {
			t.Errorf("outer server sets %s = %v; the proxy must not decide when a live connection ends",
				unwanted.name, unwanted.value)
		}
	}
}

// Start installed a listener and a server unconditionally, so a second call
// overwrote both and orphaned the first pair with no way to reach them.
func TestStartTwiceIsRefused(t *testing.T) {
	p := NewMITMProxy()
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	first := p.Addr()
	if err := p.Start("127.0.0.1:0"); err == nil {
		t.Fatal("second Start succeeded, want it refused")
	}
	if p.Addr().String() != first.String() {
		t.Fatalf("Addr changed to %v after a refused Start, want %v", p.Addr(), first)
	}
}

// Close is documented safe before Start. It used to spend the sync.Once that
// arms the shutdown guard, so a later Start produced a proxy that would happily
// detach a CONNECT it could never close again.
func TestCloseBeforeStartLeavesTheProxyClosed(t *testing.T) {
	p := NewMITMProxy()
	p.Close()

	if err := p.Start("127.0.0.1:0"); err == nil {
		p.Close()
		t.Fatal("Start after Close succeeded, want it refused")
	}
	if !p.closed() {
		t.Fatal("proxy does not report itself closed after Close")
	}
}

// The nested HTTP/2 server carrying intercepted traffic was never registered
// for shutdown, and x/net/http2 only arms graceful shutdown through
// ConfigureServer — so a live h2 session could never be drained and Shutdown
// always sat out its whole deadline. h2 is the default the MITM config offers.
func TestShutdownDrainsInterceptedHTTP2(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	ca := generateProxyTestCA(t)
	p := NewMITMProxy(WithMitmCA(ca))
	if err := p.ForwardTo("api.corp", upstream.Listener.Addr().String()); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	client := proxyHTTPClient(p.Addr().String(), ca, true)
	resp, err := client.Get("https://api.corp/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Skipf("client negotiated %s, not HTTP/2", resp.Proto)
	}

	// The session is now open and idle. Draining it means sending GOAWAY;
	// without that, Shutdown can only wait out the deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := p.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown after %v: %v, want a clean drain", time.Since(start), err)
	}
}

// Cloning a transport per request leaks it: the clone inherits a zero
// IdleConnTimeout, goes out of scope after RoundTrip with nobody to call
// CloseIdleConnections, and its connection plus read and write goroutines then
// live until the process exits. Router already fixed this per tunnel port; the
// same fix never reached here.
func TestUpstreamTransportIsReusedAcrossRequests(t *testing.T) {
	p := NewMITMProxy()
	defer p.Close()

	rt := route{target: "api.corp:443", tlsHost: "api.corp"}
	first, _, releaseFirst := p.upstreamTransport(rt, nil, false)
	defer releaseFirst()
	second, _, releaseSecond := p.upstreamTransport(rt, nil, false)
	defer releaseSecond()

	if first != second {
		t.Fatalf("upstreamTransport built a second transport for the same route (%p vs %p)", first, second)
	}
}

// Learned exclusions are keyed by whatever authority a client asked for, so the
// map must stay bounded even when nothing in it has expired yet.
func TestNoMITMEntriesStayBounded(t *testing.T) {
	p := NewMITMProxy()
	rt := route{target: "upstream:443"}
	refused := x509.UnknownAuthorityError{}

	for i := 0; i < maxNoMITMEntries+64; i++ {
		p.noteMITMFailure(fmt.Sprintf("host%d.corp:443", i), rt, refused)
	}

	p.noMITMMu.RLock()
	size := len(p.noMITM)
	p.noMITMMu.RUnlock()
	if size > maxNoMITMEntries {
		t.Fatalf("noMITM holds %d entries, want at most %d", size, maxNoMITMEntries)
	}
}
