package vtunnel_test

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
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func openHTTP1ConnectTunnel(t *testing.T, proxyAddr, authority string) (net.Conn, *bufio.Reader) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority); err != nil {
		conn.Close()
		t.Fatalf("write CONNECT: %v", err)
	}

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		t.Fatalf("read CONNECT status: %v", err)
	}
	if !strings.Contains(status, "200") {
		conn.Close()
		t.Fatalf("CONNECT failed: %s", status)
	}

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			t.Fatalf("read CONNECT headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	return conn, br
}

func TestProxyMitmHTTP2PreservesTeTrailers(t *testing.T) {
	backend := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Te"), "trailers") {
			http.Error(w, "missing TE: trailers", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/grpc")
		fmt.Fprint(w, "grpc-te-ok")
	}), &http2.Server{}))
	defer backend.Close()

	ca := generateTestCA(t)
	server := vtunnel.NewServer(vtunnel.WithProxyMitmCA(ca))
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := server.StartProxy(proxyAddr); err != nil {
		t.Fatalf("StartProxy error: %v", err)
	}
	defer server.CloseProxy()

	server.SetDomainMapping("grpc-te.test:443", backend.Listener.Addr().String())

	conn, br := openHTTP1ConnectTunnel(t, proxyAddr, "grpc-te.test:443")
	defer conn.Close()

	tlsConn := tls.Client(newBufConn(conn, br), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "grpc-te.test",
		NextProtos:         []string{"h2"},
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	defer tlsConn.Close()

	if got := tlsConn.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("expected ALPN h2, got %q", got)
	}

	h2t := &http2.Transport{}
	h2cc, err := h2t.NewClientConn(tlsConn)
	if err != nil {
		t.Fatalf("new h2 client conn: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, "https://grpc-te.test/test.Service/Method", nil)
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")

	resp, err := h2cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 round trip: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", resp.StatusCode, string(body))
	}
	if string(body) != "grpc-te-ok" {
		t.Fatalf("expected body grpc-te-ok, got %q", string(body))
	}
}

func TestProxyMitmNoSNIIpLiteralUsesConnectAuthorityForCert(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ip-mitm-ok")
	}))
	defer backend.Close()

	ca := generateTestCA(t)
	caLeaf, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		t.Fatalf("parse proxy CA: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caLeaf)

	server := vtunnel.NewServer(vtunnel.WithProxyMitmCA(ca))
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := server.StartProxy(proxyAddr); err != nil {
		t.Fatalf("StartProxy error: %v", err)
	}
	defer server.CloseProxy()

	targetIP := "203.0.113.10"
	targetAuthority := net.JoinHostPort(targetIP, "443")
	server.SetDomainMapping(targetAuthority, backend.Listener.Addr().String())

	conn, br := openHTTP1ConnectTunnel(t, proxyAddr, targetAuthority)
	defer conn.Close()

	tlsConn := tls.Client(newBufConn(conn, br), &tls.Config{
		RootCAs:    roots,
		ServerName: targetIP, // IP literals are validated but do not send SNI.
		NextProtos: []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake without SNI should succeed for %s: %v", targetIP, err)
	}
	defer tlsConn.Close()

	req, _ := http.NewRequest(http.MethodGet, "https://"+targetIP+"/", nil)
	req.Host = targetIP
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("write HTTP request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("read HTTP response: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(body) != "ip-mitm-ok" {
		t.Fatalf("expected body ip-mitm-ok, got %q", string(body))
	}
}
