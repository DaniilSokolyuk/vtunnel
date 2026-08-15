package vtunnel_test

// These tests drive MITMProxy directly, without a tunnel, to cover proxy
// behaviour in isolation. That is not how the library is normally used: see
// doc.go and example_test.go for the Client.Forward entry point, and
// router_e2e_test.go for the full sandbox-to-controlplane path.

// A mapped domain configured with a MITM CA is not always TLS traffic — h2c
// gRPC clients (e.g. grpcurl -plaintext) send the plaintext HTTP/2 preface
// over CONNECT instead of a TLS ClientHello. MITM's TLS handshake fails hard
// on that, so the proxy peeks the opening bytes and, for h2c over an HTTP/1.1
// CONNECT, terminates it without TLS to inject headers. An HTTP/2 CONNECT tunnel
// and other cleartext are piped raw.

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/vivid-money/vtunnel"
)

func TestProxyConnectHTTP1H2CFallsBackFromMITM(t *testing.T) {
	backendAddr := startH2CTrailerBackend(t, "h2c-fallback-ok")
	proxy, proxyAddr := startMitmProxy(t)
	proxy.SetDomainMapping("h2c-fallback.test:443", backendAddr)

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

	// Speak cleartext HTTP/2 straight onto the tunnel — no TLS. The proxy must
	// recognize the h2c preface and terminate it to reach the h2c backend.
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
		t.Fatalf("expected tunnel to reach upstream, got: %v", err)
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
		t.Fatalf("Grpc-Status trailer lost: resp.Trailer=%v", resp.Trailer)
	}
}

func TestProxyConnectHTTP2H2CFallsBackFromMITM(t *testing.T) {
	backendAddr := startH2CTrailerBackend(t, "h2-h2c-fallback-ok")
	proxy, proxyAddr := startMitmProxy(t)
	proxy.SetDomainMapping("h2-h2c-fallback.test:443", backendAddr)

	// HTTP/2 CONNECT to the proxy itself (RFC 8441 extended CONNECT via h2c).
	h2t := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return net.Dial(network, proxyAddr)
		},
	}

	pr, pw := io.Pipe()
	defer pw.Close()
	connectReq, err := http.NewRequest(http.MethodConnect, "http://h2-h2c-fallback.test:443", pr)
	if err != nil {
		t.Fatalf("NewRequest CONNECT: %v", err)
	}
	connectReq.Host = "h2-h2c-fallback.test:443"

	connectResp, err := h2t.RoundTrip(connectReq)
	if err != nil {
		t.Fatalf("HTTP/2 CONNECT error: %v", err)
	}
	defer connectResp.Body.Close()
	if connectResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d", connectResp.StatusCode)
	}

	// Tunnel carries cleartext HTTP/2 over an HTTP/2 CONNECT, not TLS. The h2c
	// injection path is unsafe on this response-writer-backed stream, so the
	// proxy must fall back to a raw pipe (not TLS MITM) and still reach upstream.
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
		t.Fatalf("expected tunnel to reach upstream, got: %v", err)
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
		t.Fatalf("Grpc-Status trailer lost: resp.Trailer=%v", resp.Trailer)
	}
}

// TestProxyConnectTLSStillMITMAfterPeek guards against the first-byte peek
// breaking the normal MITM path: a real TLS ClientHello (first byte 0x16) must
// still be decrypted and served, with the peeked byte preserved into tls.Server.
func TestProxyConnectTLSStillMITMAfterPeek(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "mitm-after-peek-ok")
	}))
	t.Cleanup(backend.Close)

	proxy, proxyAddr := startMitmProxy(t)
	proxy.SetDomainMapping("tls-peek.test:443", backend.Listener.Addr().String())

	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get("https://tls-peek.test/")
	if err != nil {
		t.Fatalf("HTTPS through proxy after peek change: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "mitm-after-peek-ok" {
		t.Fatalf("expected MITM to still serve, got %q", body)
	}
}

// TestProxyConnectH2CInjectsHeaders verifies the whole point of the proxy holds
// for cleartext h2c: the tunnel is terminated as HTTP/2 (no TLS) so configured
// headers reach upstream, exactly as they do on the TLS MITM path.
func TestProxyConnectH2CInjectsHeaders(t *testing.T) {
	gotAuth := make(chan string, 1)
	backend := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth <- r.Header.Get("Authorization")
		fmt.Fprint(w, "ok")
	}), &http2.Server{}))
	t.Cleanup(backend.Close)

	proxy, proxyAddr := startMitmProxy(t)
	proxy.SetDomainMapping("inject.test:443", backend.Listener.Addr().String())
	proxy.SetDomainHeaders("inject.test:443", http.Header{"Authorization": []string{"Bearer secret"}})

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := fmt.Fprintf(conn, "CONNECT inject.test:443 HTTP/1.1\r\nHost: inject.test:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := readConnectResponse(t, conn)

	h2cc, err := (&http2.Transport{}).NewClientConn(newBufConn(conn, br))
	if err != nil {
		t.Fatalf("h2 client conn: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, "http://inject.test/test", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := h2cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected tunnel to reach upstream, got: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if got := <-gotAuth; got != "Bearer secret" {
		t.Fatalf("Authorization must be injected on cleartext h2c; upstream saw %q", got)
	}
}

// TestProxyConnectPeekErrorDoesNotWedgeProxy exercises the peek-error path: a
// client that opens the tunnel then closes before sending the first byte must
// be cleaned up without wedging the proxy for subsequent tunnels.
func TestProxyConnectPeekErrorDoesNotWedgeProxy(t *testing.T) {
	backendAddr := startH2CTrailerBackend(t, "still-alive")
	proxy, proxyAddr := startMitmProxy(t)
	proxy.SetDomainMapping("recover.test:443", backendAddr)

	// First client: CONNECT, read 200, close without any tunnel bytes → peek EOF.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial proxy: %v", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT recover.test:443 HTTP/1.1\r\nHost: recover.test:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	readConnectResponse(t, conn)
	conn.Close()

	// Second client: a full h2c fallback roundtrip must still succeed.
	conn2, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial proxy (2): %v", err)
	}
	defer conn2.Close()
	conn2.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(conn2, "CONNECT recover.test:443 HTTP/1.1\r\nHost: recover.test:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT (2): %v", err)
	}
	br := readConnectResponse(t, conn2)

	h2cc, err := (&http2.Transport{}).NewClientConn(newBufConn(conn2, br))
	if err != nil {
		t.Fatalf("h2 client conn: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, "http://recover.test/test", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := h2cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("proxy did not recover after peek-error: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "still-alive" {
		t.Fatalf("expected 'still-alive', got %q", body)
	}
}

// A cleartext protocol whose first byte happens to be 0x16 (the TLS handshake
// content type) but whose following bytes are not a TLS record version must not
// be forced into the MITM TLS handshake — which would fail and kill it. The
// three-byte record check keeps it on the raw pipe to the upstream.
func TestProxyConnectCleartext0x16IsNotMistakenForTLS(t *testing.T) {
	backendAddr := startRawEchoBackend(t)
	proxy, proxyAddr := startMitmProxy(t)
	proxy.SetDomainMapping("raw16.test:443", backendAddr)

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := fmt.Fprintf(conn, "CONNECT raw16.test:443 HTTP/1.1\r\nHost: raw16.test:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := readConnectResponse(t, conn)

	// 0x16, then 0x00 0x01 — a valid TLS record needs 0x03 0x00-0x03 here, so
	// this is not TLS and must be piped raw, not run through the MITM handshake.
	// Padded past the h2c-preface length so preface detection resolves at once
	// instead of waiting for more bytes that a one-shot client won't send.
	payload := append([]byte{0x16, 0x00, 0x01}, []byte("not-tls-not-h2c-preface-payload")...)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(br, echoed); err != nil {
		t.Fatalf("raw pipe did not echo (traffic likely captured by MITM): %v", err)
	}
	if string(echoed) != string(payload) {
		t.Fatalf("expected raw echo %q, got %q", payload, echoed)
	}
}

// startRawEchoBackend starts a plain TCP proxy that echoes bytes back, closed
// via t.Cleanup. Returns its listen address.
func startRawEchoBackend(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw echo backend: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// startMitmProxy starts a proxy with a MITM CA and returns it plus its address.
// The proxy is closed via t.Cleanup.
func startMitmProxy(t *testing.T) (*vtunnel.MITMProxy, string) {
	t.Helper()
	ca := generateTestCA(t)
	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := proxy.Start(proxyAddr); err != nil {
		t.Fatalf("StartProxy error: %v", err)
	}
	t.Cleanup(proxy.Close)
	return proxy, proxyAddr
}

// startH2CTrailerBackend starts an h2c backend that returns body plus an
// unannounced Grpc-Status trailer (like a real gRPC status), closed via
// t.Cleanup. Returns its listen address.
func startH2CTrailerBackend(t *testing.T, body string) string {
	t.Helper()
	backend := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
		fmt.Fprint(w, body)
	}), &http2.Server{}))
	t.Cleanup(backend.Close)
	return backend.Listener.Addr().String()
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
