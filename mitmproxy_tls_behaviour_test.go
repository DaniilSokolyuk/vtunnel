package vtunnel_test

// The TLS half of interception: what the client is offered, what it can use,
// and what it is told when the upstream is the thing that went wrong.

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

// tunnelTLSClient opens a CONNECT tunnel and hands back a TLS client over it,
// unhandshaken, so the caller can choose what to offer.
func tunnelTLSClient(t *testing.T, proxyAddr, authority string, cfg *tls.Config) *tls.Conn {
	t.Helper()
	conn, br := openTunnel(t, proxyAddr, authority)
	_ = br
	return tls.Client(conn, cfg)
}

// An upstream that is down is an upstream problem, and a proxy that cannot say
// so is one more thing to debug. Dialling the upstream from inside the client's
// handshake meant every upstream-side failure — refused, unreachable, cleartext
// where TLS was expected, a certificate that does not check out — came back as
// one opaque `tls: internal error`, on which no retry-on-5xx and no circuit
// breaker can act. The identical outage on a cleartext route answered 502.
func TestDeadTLSUpstreamAnswers502(t *testing.T) {
	// A port with nothing behind it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("down.corp", "tls://"+dead, vtunnel.WithSNI("down.corp")); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	tc := tunnelTLSClient(t, p.Addr().String(), "down.corp:443",
		&tls.Config{ServerName: "down.corp", RootCAs: caPoolFor(t, ca)})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("the client's own handshake failed because the upstream is down: %v; "+
			"an unreachable backend is a 502, not a TLS error", err)
	}
	fmt.Fprint(tc, "GET / HTTP/1.1\r\nHost: down.corp\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %s, want 502", resp.Status)
	}
}

// ALPN is a preference list, in order. With a TLS upstream the proxy mirrors
// what that upstream negotiated, which is right — but with no upstream to
// mirror it answered from its own fixed list, so a client that put http/1.1
// first was given h2 anyway and had no way to say otherwise.
func TestALPNFollowsClientPreferenceWithNoUpstreamToMirror(t *testing.T) {
	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	p.Handle("api.corp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	for _, tc := range []struct {
		offered []string
		want    string
	}{
		{[]string{"qux", "http/1.1", "h2"}, "http/1.1"},
		{[]string{"qux", "h2", "http/1.1"}, "h2"},
		{[]string{"h2"}, "h2"},
		{[]string{"http/1.1"}, "http/1.1"},
	} {
		conn := tunnelTLSClient(t, p.Addr().String(), "api.corp:443", &tls.Config{
			ServerName: "api.corp",
			RootCAs:    caPoolFor(t, ca),
			NextProtos: tc.offered,
		})
		if err := conn.Handshake(); err != nil {
			t.Fatalf("offered %v: %v", tc.offered, err)
		}
		if got := conn.ConnectionState().NegotiatedProtocol; got != tc.want {
			t.Errorf("offered %v, negotiated %q, want %q", tc.offered, got, tc.want)
		}
		conn.Close()
	}
}

// A client that offers only protocols this proxy cannot carry is refused, not
// quietly handed one it never asked for. Following the client's order must not
// turn into inventing an answer for it (RFC 7301 §3.2).
func TestALPNRefusesWhatItCannotCarry(t *testing.T) {
	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	p.Handle("api.corp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	conn := tunnelTLSClient(t, p.Addr().String(), "api.corp:443", &tls.Config{
		ServerName: "api.corp",
		RootCAs:    caPoolFor(t, ca),
		NextProtos: []string{"imap", "smtp"},
	})
	if err := conn.Handshake(); err == nil {
		conn.Close()
		t.Fatalf("negotiated %q with a client that offered only imap and smtp",
			conn.ConnectionState().NegotiatedProtocol)
	}
}

// The generated leaf was always ECDSA, so a client whose cipher suites are all
// RSA — TLS 1.2 stacks old enough to predate ECDSA, which is what "old JVM" and
// "embedded HTTP client" usually means — could not complete a handshake with
// any intercepted domain, ever, and got only an opaque handshake failure.
func TestRSAOnlyClientCanStillBeIntercepted(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer backend.Close()

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("legacy.corp", backend.Listener.Addr().String()); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	conn := tunnelTLSClient(t, p.Addr().String(), "legacy.corp:443", &tls.Config{
		ServerName: "legacy.corp",
		RootCAs:    caPoolFor(t, ca),
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
	})
	if err := conn.Handshake(); err != nil {
		t.Fatalf("an RSA-only TLS 1.2 client cannot reach an intercepted domain: %v", err)
	}
	defer conn.Close()

	fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: legacy.corp\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("body = %q", body)
	}
}

// A modern client still gets the cheap certificate.
func TestModernClientStillGetsAnECDSALeaf(t *testing.T) {
	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	p.Handle("api.corp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	conn := tunnelTLSClient(t, p.Addr().String(), "api.corp:443", &tls.Config{
		ServerName: "api.corp",
		RootCAs:    caPoolFor(t, ca),
	})
	if err := conn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	leaf := conn.ConnectionState().PeerCertificates[0]
	if leaf.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatalf("leaf key algorithm = %v, want ECDSA for a modern client", leaf.PublicKeyAlgorithm)
	}
}

// A second connection to the same domain resumes rather than handshaking from
// scratch. It could not: the server's config — and with it the session ticket
// keys — was rebuilt for every connection, so every ticket it issued was
// undecryptable by the time it came back.
func TestTLSSessionsResume(t *testing.T) {
	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	p.Handle("api.corp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	cache := tls.NewLRUClientSessionCache(8)
	dial := func() *tls.Conn {
		conn := tunnelTLSClient(t, p.Addr().String(), "api.corp:443", &tls.Config{
			ServerName:         "api.corp",
			RootCAs:            caPoolFor(t, ca),
			ClientSessionCache: cache,
		})
		if err := conn.Handshake(); err != nil {
			t.Fatalf("handshake: %v", err)
		}
		return conn
	}

	first := dial()
	// Read one response so the session ticket that follows it is taken in.
	fmt.Fprint(first, "GET / HTTP/1.1\r\nHost: api.corp\r\n\r\n")
	if resp, err := http.ReadResponse(bufio.NewReader(first), nil); err == nil {
		io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	time.Sleep(100 * time.Millisecond)
	first.Close()

	second := dial()
	defer second.Close()
	if !second.ConnectionState().DidResume {
		t.Fatal("the second connection did not resume: the session ticket keys do not " +
			"outlive the connection that issued them, so every client pays a full handshake")
	}
}
