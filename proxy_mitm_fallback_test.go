package vtunnel

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestProxyMITMHTTP2TLSUpstreamFallbackToHTTP11(t *testing.T) {
	upstreamProto := make(chan string, 1)
	upstreamALPN := make(chan string, 1)

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case upstreamProto <- r.Proto:
		default:
		}
		if r.TLS != nil {
			select {
			case upstreamALPN <- r.TLS.NegotiatedProtocol:
			default:
			}
		}
		fmt.Fprint(w, "fallback-ok")
	}))
	upstream.EnableHTTP2 = false
	upstream.StartTLS()
	defer upstream.Close()

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

	server := NewServer(WithProxyMitmCA(ca))
	target := upstream.Listener.Addr().String()
	server.SetDomainMapping("fallback.test:443", target)
	server.tlsUpstreamMu.Lock()
	// httptest TLS cert is issued for example.com.
	server.tlsUpstream[target] = "example.com"
	server.tlsUpstreamMu.Unlock()

	handler := &proxyHandler{
		server:    server,
		certCache: certCache,
		transport: http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: rootCAs},
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = http.Serve(ln, handler)
	}()
	defer func() {
		ln.Close()
		<-done
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := fmt.Fprintf(conn, "CONNECT fallback.test:443 HTTP/1.1\r\nHost: fallback.test:443\r\n\r\n"); err != nil {
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

	tunnelConn := newBufferedConn(conn, br)
	tlsConn := tls.Client(tunnelConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "fallback.test",
		NextProtos:         []string{"h2"},
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake with MITM proxy: %v", err)
	}
	defer tlsConn.Close()
	if got := tlsConn.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("expected inner ALPN h2, got %q", got)
	}

	h2t := &http2.Transport{}
	h2c, err := h2t.NewClientConn(tlsConn)
	if err != nil {
		t.Fatalf("new h2 client conn: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://fallback.test/test", nil)
	resp, err := h2c.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 round trip through MITM: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "fallback-ok" {
		t.Fatalf("expected body fallback-ok, got %q", string(body))
	}

	select {
	case proto := <-upstreamProto:
		if proto != "HTTP/1.1" {
			t.Fatalf("expected upstream HTTP/1.1, got %s", proto)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for upstream protocol")
	}

	select {
	case alpn := <-upstreamALPN:
		if alpn == "h2" {
			t.Fatalf("expected upstream ALPN fallback from h2, got %q", alpn)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for upstream ALPN")
	}
}

func generateProxyTestCA(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "vtunnel proxy test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
}
