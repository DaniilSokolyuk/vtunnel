package vtunnel_test

// Helpers for the tests that drive the proxy from the outside, the way a client
// does: a proxy with one credential-carrying route — which is what makes "was
// this intercepted" answerable, since a pipe cannot inject a header — and the
// two steps of reaching it, CONNECT and then TLS inside the tunnel.

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

func gapProxy(t *testing.T, upstream string) (addr string, ca tls.Certificate) {
	t.Helper()
	ca = generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("probe.test", upstream,
		vtunnel.WithHeader("Authorization", "Bearer injected")); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(p.Close)
	return p.Addr().String(), ca
}

func caPoolFor(t *testing.T, ca tls.Certificate) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	leaf, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	pool.AddCert(leaf)
	return pool
}

// connectThenTLS opens a CONNECT tunnel, writes trailing after the request
// headers, and completes a TLS handshake inside it.
func connectThenTLS(t *testing.T, proxyAddr, authority, serverName, trailing string, ca tls.Certificate) *tls.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n%s", authority, authority, trailing)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: %s", resp.Status)
	}

	tc := tls.Client(conn, &tls.Config{ServerName: serverName, RootCAs: caPoolFor(t, ca)})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("TLS handshake inside the tunnel: %v", err)
	}
	return tc
}

func requestOver(t *testing.T, conn net.Conn, request string) *http.Response {
	t.Helper()
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp
}
