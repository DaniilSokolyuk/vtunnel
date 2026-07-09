package vtunnel_test

// A mapped domain configured with a MITM CA is not always TLS traffic — h2c
// gRPC clients (e.g. grpcurl -plaintext) send the plaintext HTTP/2 preface
// over CONNECT instead of a TLS ClientHello. MITM's TLS handshake fails hard
// on that and kills the tunnel, so the proxy must peek the first byte and
// fall back to the raw byte pipe the no-MITM path already uses.
//
// Covers both CONNECT dispatch paths: HTTP/1.x (hijack) and HTTP/2 (RFC 8441
// extended CONNECT) — grpc-go may use either depending on how it reaches
// the proxy.

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/vivid-money/vtunnel"
)

func TestProxyConnectHTTP1H2CFallsBackFromMITM(t *testing.T) {
	backend := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0") // unannounced, like a real gRPC status trailer
		fmt.Fprint(w, "h2c-fallback-ok")
	}), &http2.Server{}))
	defer backend.Close()

	ca := generateTestCA(t)
	server := vtunnel.NewServer(vtunnel.WithProxyMitmCA(ca))
	proxyPort := freePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if err := server.StartProxy(proxyAddr); err != nil {
		t.Fatalf("StartProxy error: %v", err)
	}
	defer server.CloseProxy()

	server.SetDomainMapping("h2c-fallback.test:443", backend.Listener.Addr().String())

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := fmt.Fprintf(conn, "CONNECT h2c-fallback.test:443 HTTP/1.1\r\nHost: h2c-fallback.test:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	br := readConnectResponse(t, conn)

	// Speak cleartext HTTP/2 straight onto the tunnel — no TLS. A correctly
	// falling-back proxy pipes this through to the h2c backend unmodified.
	tunnelConn := newBufConn(conn, br)
	h2t := &http2.Transport{}
	h2cc, err := h2t.NewClientConn(tunnelConn)
	if err != nil {
		t.Fatalf("h2 client conn: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "http://h2c-fallback.test/test", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := h2cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected raw fallback to reach upstream, got: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body) // trailers only arrive after the body is drained
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "h2c-fallback-ok" {
		t.Fatalf("expected 'h2c-fallback-ok', got %q", body)
	}
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("Grpc-Status trailer lost through raw fallback: resp.Trailer=%v", resp.Trailer)
	}
}

func TestProxyConnectHTTP2H2CFallsBackFromMITM(t *testing.T) {
	backend := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
		fmt.Fprint(w, "h2-h2c-fallback-ok")
	}), &http2.Server{}))
	defer backend.Close()

	ca := generateTestCA(t)
	server := vtunnel.NewServer(vtunnel.WithProxyMitmCA(ca))
	proxyPort := freePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if err := server.StartProxy(proxyAddr); err != nil {
		t.Fatalf("StartProxy error: %v", err)
	}
	defer server.CloseProxy()

	server.SetDomainMapping("h2-h2c-fallback.test:443", backend.Listener.Addr().String())

	// HTTP/2 CONNECT to the proxy itself (RFC 8441 extended CONNECT via h2c).
	h2t := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return net.Dial(network, proxyAddr)
		},
	}

	pr, pw := io.Pipe()
	connectReq, err := http.NewRequest(http.MethodConnect, "http://h2-h2c-fallback.test:443", pr)
	if err != nil {
		t.Fatalf("NewRequest CONNECT: %v", err)
	}
	connectReq.Host = "h2-h2c-fallback.test:443"

	connectResp, err := h2t.RoundTrip(connectReq)
	if err != nil {
		t.Fatalf("HTTP/2 CONNECT error: %v", err)
	}
	if connectResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d", connectResp.StatusCode)
	}

	// Tunnel carries cleartext HTTP/2, not TLS — the proxy must recognize
	// this and fall back to raw piping instead of attempting MITM.
	h2Conn := newHTTP2Conn(pw, connectResp.Body)
	innerH2t := &http2.Transport{}
	h2cc, err := innerH2t.NewClientConn(h2Conn)
	if err != nil {
		t.Fatalf("h2 client conn over CONNECT tunnel: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "http://h2-h2c-fallback.test/test", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := h2cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected raw fallback to reach upstream, got: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "h2-h2c-fallback-ok" {
		t.Fatalf("expected 'h2-h2c-fallback-ok', got %q", body)
	}
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("Grpc-Status trailer lost through raw fallback: resp.Trailer=%v", resp.Trailer)
	}

	pw.Close()
}

// readConnectResponse reads the CONNECT response line and headers off conn,
// failing the test on anything but 200, and returns the buffered reader so
// callers can keep reading tunneled bytes without losing anything net/http
// already buffered.
func readConnectResponse(t *testing.T, conn net.Conn) *bufio.Reader {
	t.Helper()
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
	return br
}
