package vtunnel

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

// The proxy mirrors the upstream's ALPN back to the client, but the base config
// carried no NextProtos of its own — so a TLS upstream that negotiates no ALPN
// at all (a server that simply does not configure it) left the mirrored config
// empty and the proxy answered ServerHello with no ALPN extension. Clients that
// require one, gRPC among them, broke on a forward with no headers and no
// handler: nothing but a plain address.
func TestMITMOffersALPNWhenUpstreamNegotiatesNone(t *testing.T) {
	upCA := testCA(t, "upstream CA")
	upstreamAddr := tlsServerWithoutALPN(t, "noalpn.test", upCA)

	proxy, proxyAddr, ca := startCoverageProxy(t, func(p *MITMProxy) {
		p.SetTransportTLSConfig(&tls.Config{RootCAs: poolFor(t, upCA)})
	})
	proxy.ForwardTo("noalpn.test:443", "tls://"+upstreamAddr, WithSNI("noalpn.test"))

	state := clientHandshakeThroughProxy(t, proxyAddr, "noalpn.test", ca, []string{"h2", "http/1.1"})
	if state.NegotiatedProtocol == "" {
		t.Fatal("client offered {h2, http/1.1} and the proxy answered without ALPN; " +
			"a client that requires it cannot use this route")
	}
}

// Narrowing the client's offer to what this proxy can carry must not produce an
// empty list either: a client offering only protocols the proxy cannot proxy
// should still get a usable answer rather than silence.
func TestHTTPALPNNeverNarrowsToNothing(t *testing.T) {
	if got := httpALPN([]string{"h2", "http/1.1"}); len(got) == 0 {
		t.Fatal("httpALPN dropped protocols it can carry")
	}
	if got := httpALPN([]string{"spdy/3", "ftp"}); len(got) != 0 {
		t.Fatalf("httpALPN kept %v, none of which this proxy speaks", got)
	}
}

// A pre-established upstream is reused for later requests, but the transport is
// chosen once from the first connection's protocol. Leaving the full offer in
// the config let a redial negotiate something else — http/1.1 under an
// http2.Transport waiting for h2 — so the session broke on reconnect rather
// than at setup.
func TestUpstreamConfigPinsTheNegotiatedProtocol(t *testing.T) {
	upCA := testCA(t, "pinning CA")
	addr := tlsEchoServerAuth(t, "pinned-alpn.test", upCA, "up", tls.NoClientCert)

	p := NewMITMProxy(WithMitmCA(testCA(t, "proxy CA")))
	p.SetTransportTLSConfig(&tls.Config{RootCAs: poolFor(t, upCA)})

	up, err := p.dialTLSUpstream(t.Context(), addr, "pinned-alpn.test", []string{"h2", "http/1.1"})
	if err != nil {
		t.Fatalf("dialTLSUpstream: %v", err)
	}
	defer up.close()

	proto := up.proto()
	if proto == "" {
		t.Skip("upstream negotiated no protocol; nothing to pin")
	}
	if got := up.cfg.NextProtos; len(got) != 1 || got[0] != proto {
		t.Fatalf("redial config offers %v, want only the negotiated %q — a later "+
			"connection could settle on something the chosen transport cannot speak", got, proto)
	}
}

// --- helpers ---

// tlsServerWithoutALPN serves TLS with no NextProtos configured, so it
// negotiates no application protocol at all.
func tlsServerWithoutALPN(t *testing.T, hostname string, ca tls.Certificate) string {
	t.Helper()

	cache, err := newCertCache(ca)
	if err != nil {
		t.Fatalf("newCertCache: %v", err)
	}
	leaf, _, err := cache.signHost(hostname, keyECDSA, time.Now())
	if err != nil {
		t.Fatalf("signHost: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{*leaf}} // deliberately no NextProtos
	srv := &http.Server{
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "up") }),
		TLSConfig: cfg,
	}
	go srv.Serve(tls.NewListener(ln, cfg))
	t.Cleanup(func() { srv.Close() })

	return ln.Addr().String()
}

// clientHandshakeThroughProxy opens a CONNECT tunnel by hand and completes the
// inner TLS handshake, returning what was negotiated.
func clientHandshakeThroughProxy(t *testing.T, proxyAddr, host string, ca tls.Certificate, alpn []string) tls.ConnectionState {
	t.Helper()

	raw, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { raw.Close() })

	fmt.Fprintf(raw, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host)
	resp, err := http.ReadResponse(bufio.NewReader(raw), nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	caLeaf, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caLeaf)

	conn := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: roots, NextProtos: alpn})
	if err := conn.Handshake(); err != nil {
		t.Fatalf("inner handshake: %v", err)
	}
	return conn.ConnectionState()
}
