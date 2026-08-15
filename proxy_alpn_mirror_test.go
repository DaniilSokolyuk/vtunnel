package vtunnel

// These tests drive MITMProxy directly, without a tunnel, to cover proxy
// behaviour in isolation. That is not how the library is normally used: see
// doc.go and example_test.go for the Client.Forward entry point, and
// router_e2e_test.go for the full sandbox-to-controlplane path.

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The proxy establishes the upstream TLS connection before finishing the
// client's handshake, so the protocol it offers the client is one the upstream
// actually agreed to. Previously {h2, http/1.1} was offered blind, letting a
// client pick h2 against an upstream that cannot speak it.
func TestProxyMITMMirrorsUpstreamALPN(t *testing.T) {
	for _, tc := range []struct {
		name          string
		upstreamHTTP2 bool
		clientOffers  []string
		wantClient    string
	}{
		{
			name:         "http1 upstream is not advertised as h2",
			clientOffers: []string{"h2", "http/1.1"},
			wantClient:   "http/1.1",
		},
		{
			name:          "h2 upstream is advertised as h2",
			upstreamHTTP2: true,
			clientOffers:  []string{"h2", "http/1.1"},
			wantClient:    "h2",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxyAddr, cleanup := newMirrorTestProxy(t, tc.upstreamHTTP2)
			defer cleanup()

			tlsConn := connectAndHandshake(t, proxyAddr, "mirror.test:443", tc.clientOffers)
			defer tlsConn.Close()

			if got := tlsConn.ConnectionState().NegotiatedProtocol; got != tc.wantClient {
				t.Fatalf("client ALPN = %q, want %q (upstream http2=%v)", got, tc.wantClient, tc.upstreamHTTP2)
			}
		})
	}
}

// An h2-only client against an HTTP/1.1-only upstream must still work: the
// proxy re-issues requests, so it can translate between the two rather than
// failing the handshake with no_application_protocol.
func TestProxyMITMTranslatesForH2OnlyClient(t *testing.T) {
	proxyAddr, cleanup := newMirrorTestProxy(t, false)
	defer cleanup()

	tlsConn := connectAndHandshake(t, proxyAddr, "mirror.test:443", []string{"h2"})
	defer tlsConn.Close()

	if got := tlsConn.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("client ALPN = %q, want h2 (proxy should translate, not refuse)", got)
	}
}

// newMirrorTestProxy starts an HTTPS upstream and a MITM proxy mapping
// mirror.test:443 to it, and returns the proxy address.
func newMirrorTestProxy(t *testing.T, upstreamHTTP2 bool) (string, func()) {
	t.Helper()

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "mirror-ok")
	}))
	upstream.EnableHTTP2 = upstreamHTTP2
	upstream.StartTLS()

	upstreamCert, err := x509.ParseCertificate(upstream.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse upstream cert: %v", err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(upstreamCert)

	ca := generateProxyTestCA(t)
	certCache, err := newCertCache(ca)
	if err != nil {
		t.Fatalf("newCertCache: %v", err)
	}

	proxy := NewMITMProxy(WithMitmCA(ca))
	proxy.certCache = certCache
	proxy.transport = http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootCAs}}

	target := upstream.Listener.Addr().String()
	proxy.SetDomainMapping("mirror.test:443", target)
	// httptest TLS certs are issued for example.com.
	proxy.SetTLSUpstream(target, "example.com")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = http.Serve(ln, proxy)
	}()

	return ln.Addr().String(), func() {
		ln.Close()
		<-done
		upstream.Close()
	}
}

// connectAndHandshake performs CONNECT against the proxy and then a TLS
// handshake inside the tunnel, offering the given ALPN list.
func connectAndHandshake(t *testing.T, proxyAddr, authority string, alpn []string) *tls.Conn {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT failed: %s", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	host, _, _ := net.SplitHostPort(authority)
	tlsConn := tls.Client(newBufferedConn(conn, br), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		NextProtos:         alpn,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake with MITM proxy: %v", err)
	}
	return tlsConn
}

func TestCertCacheRenewsAndStaysBounded(t *testing.T) {
	ca := generateProxyTestCA(t)
	cache, err := newCertCache(ca)
	if err != nil {
		t.Fatalf("newCertCache: %v", err)
	}

	hello := &tls.ClientHelloInfo{ServerName: "cache.test"}

	first, err := cache.getCert(hello, "")
	if err != nil {
		t.Fatalf("getCert: %v", err)
	}
	again, err := cache.getCert(hello, "")
	if err != nil {
		t.Fatalf("getCert: %v", err)
	}
	if first != again {
		t.Fatal("second lookup must hit the cache")
	}

	// Push the entry past its renewal point; the next lookup must reissue.
	cache.mu.Lock()
	cache.certs["cache.test"].renewAt = time.Now().Add(-time.Second)
	cache.mu.Unlock()

	renewed, err := cache.getCert(hello, "")
	if err != nil {
		t.Fatalf("getCert after expiry: %v", err)
	}
	if renewed == first {
		t.Fatal("cert past its renewal point must be regenerated, not served")
	}

	// A client walking many SNI names must not grow the cache without bound.
	for i := range maxCachedCerts + 8 {
		host := fmt.Sprintf("h%d.cache.test", i)
		if _, err := cache.getCert(&tls.ClientHelloInfo{ServerName: host}, ""); err != nil {
			t.Fatalf("getCert %s: %v", host, err)
		}
	}
	cache.mu.Lock()
	size := len(cache.certs)
	cache.mu.Unlock()
	if size > maxCachedCerts {
		t.Fatalf("cache grew to %d entries, want <= %d", size, maxCachedCerts)
	}
}

// The generated leaf must be usable and chain to the configured CA.
func TestCertCacheLeafChainsToCA(t *testing.T) {
	ca := generateProxyTestCA(t)
	cache, err := newCertCache(ca)
	if err != nil {
		t.Fatalf("newCertCache: %v", err)
	}

	cert, err := cache.getCert(&tls.ClientHelloInfo{ServerName: "leaf.test"}, "")
	if err != nil {
		t.Fatalf("getCert: %v", err)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(cache.caX509)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "leaf.test", Roots: roots}); err != nil {
		t.Fatalf("leaf does not chain to CA: %v", err)
	}

	if leaf.SerialNumber.BitLen() < 32 {
		t.Fatalf("serial %d looks predictable, want a random 128-bit value", leaf.SerialNumber)
	}
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got > leafValidity+leafBackdate+time.Minute {
		t.Fatalf("leaf validity window %v is longer than expected", got)
	}
}
