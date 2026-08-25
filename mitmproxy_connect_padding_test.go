package vtunnel_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

// Blank lines after the CONNECT headers.
//
// RFC 9112 §2.2 lets a recipient ignore them and real clients send them, but
// left in place they become the first bytes of the tunnel: the ClientHello
// behind them no longer looks like TLS, so the connection is quietly piped
// instead of intercepted — and on the piping path they reach the upstream in
// front of its ClientHello and break the handshake. Telling them from a payload
// that legitimately begins with a line ending is the other half of the problem.

// Interception survives them, and the credential is still injected — which is
// what the assertion checks, because a test that only looked at the status code
// would pass on the pipe too.
func TestExtraCRLFAfterConnectStillIntercepts(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "auth=%s", r.Header.Get("Authorization"))
	}))
	defer backend.Close()

	addr, ca := gapProxy(t, backend.Listener.Addr().String())

	tc := connectThenTLS(t, addr, "probe.test:443", "probe.test", "\r\n\r\n", ca)
	resp := requestOver(t, tc, "GET / HTTP/1.1\r\nHost: probe.test\r\n\r\n")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != "auth=Bearer injected" {
		t.Fatalf("body = %q: the tunnel was piped instead of intercepted, so the "+
			"credential never made it", body)
	}
}

// The same padding through the sandbox egress proxy, where it used to be copied
// verbatim into the upstream and arrive in front of the ClientHello.
func TestExtraCRLFThroughTheEgressProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "auth=%s", r.Header.Get("Authorization"))
	}))
	defer backend.Close()

	ts, server := startTunnelServer(t)
	defer ts.Close()

	egressAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := server.StartProxy(egressAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	ca := generateTestCA(t)
	client := vtunnel.NewClient(wsURL(ts), vtunnel.WithMitm(ca))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()
	if err := client.Proxy().ForwardTo("probe.test", backend.Listener.Addr().String(),
		vtunnel.WithHeader("Authorization", "Bearer injected")); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	tc := connectThenTLS(t, egressAddr, "probe.test:443", "probe.test", "\r\n", ca)
	resp := requestOver(t, tc, "GET / HTTP/1.1\r\nHost: probe.test\r\n\r\n")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != "auth=Bearer injected" {
		t.Fatalf("body = %q, want the injected credential", body)
	}
}

// Padding must not be mistaken for payload: a tunnel that really does open with
// CRLFs still carries them.
func TestConnectPaddingDoesNotEatPayload(t *testing.T) {
	echo, _ := tcpEcho(t, "raw")

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("raw.test:9999", echo); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	conn, err := net.DialTimeout("tcp", p.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Two CRLFs of padding, then a payload that itself begins with one.
	fmt.Fprint(conn, "CONNECT raw.test:9999 HTTP/1.1\r\nHost: raw.test:9999\r\n\r\n\r\n\r\n")
	br := bufio.NewReader(conn)
	if _, err := http.ReadResponse(br, nil); err != nil {
		t.Fatalf("CONNECT: %v", err)
	}

	fmt.Fprint(conn, "\r\n\r\n\r\n\r\n\r\n\r\n\r\nPAYLOAD")
	conn.(*net.TCPConn).CloseWrite()
	answer, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.HasSuffix(string(answer), "PAYLOAD") {
		t.Fatalf("target received %q, want it to end in PAYLOAD", answer)
	}
}

func TestConnectPaddingLeavesARawPayloadIntact(t *testing.T) {
	echo, _ := tcpEcho(t, "raw")

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("raw.test:9000", echo); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	conn, err := net.DialTimeout("tcp", p.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	fmt.Fprint(conn, "CONNECT raw.test:9000 HTTP/1.1\r\nHost: raw.test:9000\r\n\r\n")
	br := bufio.NewReader(conn)
	if _, err := http.ReadResponse(br, nil); err != nil {
		t.Fatalf("CONNECT: %v", err)
	}

	// A binary message that begins with a line ending, sent as one write once
	// the tunnel is up. Nothing here is padding.
	payload := "\r\n\x01\x02BINARY"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	conn.(*net.TCPConn).CloseWrite()

	answer, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if want := "raw: " + payload; string(answer) != want {
		t.Fatalf("the target received %q, want %q", strings.TrimPrefix(string(answer), "raw: "), payload)
	}
}
