package vtunnel_test

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

	"github.com/DaniilSokolyuk/vtunnel"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func TestProxyPlainHTTPMapped(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "proxy-ok")
	}))
	defer backend.Close()

	server := vtunnel.NewServer()
	proxyPort := freePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if err := server.StartProxy(proxyAddr); err != nil {
		t.Fatalf("StartProxy error: %v", err)
	}
	defer server.CloseProxy()

	server.SetDomainMapping("example.test:80", backend.Listener.Addr().String())

	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("Proxy URL parse error: %v", err)
	}

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Get("http://example.test/hello")
	if err != nil {
		t.Fatalf("Proxy GET error: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "proxy-ok" {
		t.Fatalf("Unexpected body: %q", string(body))
	}
}

func TestProxyConnectMapped(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Echo listen error: %v", err)
	}
	defer echoLn.Close()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	server := vtunnel.NewServer()
	proxyPort := freePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if err := server.StartProxy(proxyAddr); err != nil {
		t.Fatalf("StartProxy error: %v", err)
	}
	defer server.CloseProxy()

	server.SetDomainMapping("example.test:443", echoLn.Addr().String())

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial proxy error: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	_, err = fmt.Fprintf(conn, "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
	if err != nil {
		t.Fatalf("CONNECT write error: %v", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("CONNECT read status error: %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("Unexpected CONNECT status: %q", statusLine)
	}

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("CONNECT read headers error: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	payload := []byte("proxy-echo")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Tunnel write error: %v", err)
	}

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("Tunnel read error: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("Unexpected echo: %q", string(buf))
	}
}

func TestProxyHTTPSNoMitmFails(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "should-not-reach")
	}))
	defer backend.Close()

	server := vtunnel.NewServer() // no MITM CA
	proxyPort := freePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if err := server.StartProxy(proxyAddr); err != nil {
		t.Fatalf("StartProxy error: %v", err)
	}
	defer server.CloseProxy()

	server.SetDomainMapping("example.test:443", backend.Listener.Addr().String())

	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("Proxy URL parse error: %v", err)
	}

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	_, err = client.Get("https://example.test/")
	if err == nil {
		t.Fatal("Expected TLS handshake error, got nil")
	}
	t.Logf("Expected error: %v", err)
}

func TestProxyHTTPSMitm(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "mitm-ok")
	}))
	defer backend.Close()

	ca := generateTestCA(t)
	server := vtunnel.NewServer(vtunnel.WithProxyMitmCA(ca))
	proxyPort := freePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if err := server.StartProxy(proxyAddr); err != nil {
		t.Fatalf("StartProxy error: %v", err)
	}
	defer server.CloseProxy()

	server.SetDomainMapping("google.com:443", backend.Listener.Addr().String())

	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("Proxy URL parse error: %v", err)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Get("https://google.com/")
	if err != nil {
		t.Fatalf("HTTPS GET through proxy error: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "mitm-ok" {
		t.Fatalf("Expected 'mitm-ok', got %q", string(body))
	}
}

// h2cClient creates an HTTP/2 cleartext client that connects through the given proxy address.
func h2cClient(proxyAddr string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return net.Dial(network, proxyAddr)
			},
		},
	}
}

func TestProxyHTTP2PlainHTTP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "h2-proxy-ok")
	}))
	defer backend.Close()

	server := vtunnel.NewServer()
	proxyPort := freePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if err := server.StartProxy(proxyAddr); err != nil {
		t.Fatalf("StartProxy error: %v", err)
	}
	defer server.CloseProxy()

	server.SetDomainMapping("example.test:80", backend.Listener.Addr().String())

	client := h2cClient(proxyAddr)

	resp, err := client.Get("http://example.test/hello")
	if err != nil {
		t.Fatalf("HTTP/2 proxy GET error: %v", err)
	}
	defer resp.Body.Close()

	if resp.ProtoMajor != 2 {
		t.Fatalf("Expected HTTP/2 response, got HTTP/%d", resp.ProtoMajor)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "h2-proxy-ok" {
		t.Fatalf("Unexpected body: %q", string(body))
	}
}

func TestProxyHTTP2Connect(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Echo listen error: %v", err)
	}
	defer echoLn.Close()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	server := vtunnel.NewServer()
	proxyPort := freePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if err := server.StartProxy(proxyAddr); err != nil {
		t.Fatalf("StartProxy error: %v", err)
	}
	defer server.CloseProxy()

	server.SetDomainMapping("echo.test:443", echoLn.Addr().String())

	// HTTP/2 CONNECT via h2c
	h2t := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return net.Dial(network, proxyAddr)
		},
	}

	pr, pw := io.Pipe()
	req, _ := http.NewRequest(http.MethodConnect, "http://echo.test:443", pr)
	req.Host = "echo.test:443"

	resp, err := h2t.RoundTrip(req)
	if err != nil {
		t.Fatalf("HTTP/2 CONNECT error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}

	payload := []byte("h2-echo-test")
	go func() {
		pw.Write(payload)
		pw.Close()
	}()

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(resp.Body, buf); err != nil {
		t.Fatalf("HTTP/2 tunnel read error: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("Expected %q, got %q", string(payload), string(buf))
	}
}

func TestProxyHTTP2Mitm(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "h2-mitm-ok")
	}))
	defer backend.Close()

	ca := generateTestCA(t)
	server := vtunnel.NewServer(vtunnel.WithProxyMitmCA(ca))
	proxyPort := freePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if err := server.StartProxy(proxyAddr); err != nil {
		t.Fatalf("StartProxy error: %v", err)
	}
	defer server.CloseProxy()

	server.SetDomainMapping("secure.test:443", backend.Listener.Addr().String())

	// HTTP/2 CONNECT to proxy via h2c, then TLS handshake inside the tunnel (MITM)
	h2t := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return net.Dial(network, proxyAddr)
		},
	}

	// Send CONNECT via HTTP/2
	pr, pw := io.Pipe()
	connectReq, _ := http.NewRequest(http.MethodConnect, "http://secure.test:443", pr)
	connectReq.Host = "secure.test:443"

	connectResp, err := h2t.RoundTrip(connectReq)
	if err != nil {
		t.Fatalf("HTTP/2 CONNECT error: %v", err)
	}
	if connectResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d", connectResp.StatusCode)
	}

	// Wrap the h2 stream as a net.Conn, then do TLS handshake
	h2Conn := newHTTP2Conn(pw, connectResp.Body)
	tlsConn := tls.Client(h2Conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "secure.test",
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake over HTTP/2 tunnel: %v", err)
	}

	// Send an HTTP request through the TLS-over-H2 tunnel
	httpReq, _ := http.NewRequest("GET", "https://secure.test/", nil)
	httpReq.Host = "secure.test"
	if err := httpReq.Write(tlsConn); err != nil {
		t.Fatalf("Write HTTP request: %v", err)
	}

	httpResp, err := http.ReadResponse(bufio.NewReader(tlsConn), httpReq)
	if err != nil {
		t.Fatalf("Read HTTP response: %v", err)
	}
	defer httpResp.Body.Close()

	body, _ := io.ReadAll(httpResp.Body)
	if string(body) != "h2-mitm-ok" {
		t.Fatalf("Expected 'h2-mitm-ok', got %q", string(body))
	}

	tlsConn.Close()
	pw.Close()
}

// TestProxyMitmHTTP2Inner tests MITM where the client speaks HTTP/2 inside the
// TLS tunnel (like gRPC does). The proxy must negotiate h2 via ALPN and serve
// HTTP/2 on the decrypted connection, not just HTTP/1.1.
func TestProxyMitmHTTP2Inner(t *testing.T) {
	// h2c backend (HTTP/2 cleartext)
	h2cHandler := h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		fmt.Fprint(w, "grpc-ok")
	}), &http2.Server{})
	backend := httptest.NewServer(h2cHandler)
	defer backend.Close()

	ca := generateTestCA(t)
	server := vtunnel.NewServer(vtunnel.WithProxyMitmCA(ca))
	proxyPort := freePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if err := server.StartProxy(proxyAddr); err != nil {
		t.Fatalf("StartProxy error: %v", err)
	}
	defer server.CloseProxy()

	server.SetDomainMapping("grpc.test:443", backend.Listener.Addr().String())

	// Connect to proxy, send CONNECT, get a raw tunnel
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	fmt.Fprintf(conn, "CONNECT grpc.test:443 HTTP/1.1\r\nHost: grpc.test:443\r\n\r\n")
	br := bufio.NewReader(conn)
	status, _ := br.ReadString('\n')
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT failed: %s", status)
	}
	for {
		line, _ := br.ReadString('\n')
		if line == "\r\n" {
			break
		}
	}

	// Wrap buffered reader + conn as net.Conn for TLS
	tunnelConn := newBufConn(conn, br)

	// TLS handshake requesting h2 via ALPN
	tlsConn := tls.Client(tunnelConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "grpc.test",
		NextProtos:         []string{"h2"},
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	negotiated := tlsConn.ConnectionState().NegotiatedProtocol
	if negotiated != "h2" {
		t.Fatalf("Expected ALPN h2, got %q", negotiated)
	}

	// Use HTTP/2 client transport over the TLS connection
	h2t := &http2.Transport{}
	h2cc, err := h2t.NewClientConn(tlsConn)
	if err != nil {
		t.Fatalf("h2 client conn: %v", err)
	}

	req, _ := http.NewRequest("POST", "https://grpc.test/test.Service/Method", nil)
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := h2cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "grpc-ok" {
		t.Fatalf("Expected 'grpc-ok', got %q", body)
	}
	t.Logf("HTTP/2 inside MITM tunnel: OK (ALPN=%s)", negotiated)
}

// bufConn wraps a net.Conn with a bufio.Reader to drain buffered data first.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func newBufConn(c net.Conn, r *bufio.Reader) *bufConn {
	return &bufConn{Conn: c, r: r}
}

func (c *bufConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// newHTTP2Conn wraps a pipe writer (request body) and response body into an io.ReadWriteCloser.
type http2Conn struct {
	w *io.PipeWriter
	r io.ReadCloser
}

func newHTTP2Conn(w *io.PipeWriter, r io.ReadCloser) *http2Conn {
	return &http2Conn{w: w, r: r}
}

func (c *http2Conn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *http2Conn) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *http2Conn) Close() error {
	c.w.Close()
	return c.r.Close()
}

// net.Conn stubs for tls.Client
func (c *http2Conn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *http2Conn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *http2Conn) SetDeadline(time.Time) error      { return nil }
func (c *http2Conn) SetReadDeadline(time.Time) error  { return nil }
func (c *http2Conn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "h2" }
func (dummyAddr) String() string  { return "h2-test" }
