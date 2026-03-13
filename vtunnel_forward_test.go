package vtunnel_test

import (
	"bufio"
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
)

// TestDomainForwardHTTP tests domain-based forwarding through the HTTP proxy.
// Forward registers a domain, proxy routes plain HTTP by Host header → tunnel → backend.
func TestDomainForwardHTTP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "forward-ok")
	}))
	defer backend.Close()

	ts, server := startTunnelServer(t)
	defer ts.Close()

	proxyPort := freePort(t)
	if err := server.StartProxy(fmt.Sprintf("127.0.0.1:%d", proxyPort)); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	client := vtunnel.NewClient(wsURL(ts))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	if err := client.Forward("app.test", backend.Listener.Addr().String()); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	httpClient := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	resp, err := httpClient.Get("http://app.test/hello")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "forward-ok" {
		t.Fatalf("expected 'forward-ok', got %q", body)
	}
}

// TestDomainForwardCONNECT tests domain-based forwarding through CONNECT proxy.
func TestDomainForwardCONNECT(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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

	ts, server := startTunnelServer(t)
	defer ts.Close()

	proxyPort := freePort(t)
	if err := server.StartProxy(fmt.Sprintf("127.0.0.1:%d", proxyPort)); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	client := vtunnel.NewClient(wsURL(ts))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	// Forward with explicit port
	if err := client.Forward("secure.test:443", echoLn.Addr().String()); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), 2*time.Second)
	if err != nil {
		t.Fatalf("Dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	fmt.Fprintf(conn, "CONNECT secure.test:443 HTTP/1.1\r\nHost: secure.test:443\r\n\r\n")
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

	payload := []byte("echo-forward")
	conn.Write(payload)
	buf := make([]byte, len(payload))
	io.ReadFull(br, buf)
	if string(buf) != string(payload) {
		t.Fatalf("expected %q, got %q", payload, buf)
	}
}

// TestDomainForwardSameDomainTarget tests forwarding where domain and target host match
// (e.g. Forward("google.com:443", "google.com:443")) — passthrough without MITM.
func TestDomainForwardSameDomainTarget(t *testing.T) {
	ts, server := startTunnelServer(t)
	defer ts.Close()

	proxyPort := freePort(t)
	if err := server.StartProxy(fmt.Sprintf("127.0.0.1:%d", proxyPort)); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	client := vtunnel.NewClient(wsURL(ts))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	if err := client.Forward("google.com:443", "google.com:443"); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	httpClient := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	resp, err := httpClient.Get("https://google.com/")
	if err != nil {
		t.Fatalf("GET https://google.com via tunnel: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	t.Logf("https://google.com -> %d", resp.StatusCode)
}

// TestDomainForwardHostnameOnly tests that a domain without port matches both :80 and :443.
func TestDomainForwardHostnameOnly(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hostname-ok")
	}))
	defer backend.Close()

	ts, server := startTunnelServer(t)
	defer ts.Close()

	proxyPort := freePort(t)
	if err := server.StartProxy(fmt.Sprintf("127.0.0.1:%d", proxyPort)); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	client := vtunnel.NewClient(wsURL(ts))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	// Forward without port — should match :80 and :443
	if err := client.Forward("wild.test", backend.Listener.Addr().String()); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Test :80 via plain HTTP
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	httpClient := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp, err := httpClient.Get("http://wild.test/")
	if err != nil {
		t.Fatalf("HTTP GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Test :443 via CONNECT
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), 2*time.Second)
	if err != nil {
		t.Fatalf("Dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	fmt.Fprintf(conn, "CONNECT wild.test:443 HTTP/1.1\r\nHost: wild.test:443\r\n\r\n")
	br := bufio.NewReader(conn)
	status, _ := br.ReadString('\n')
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT failed: %s", status)
	}
}

// TestDomainForwardMultipleSameTarget tests multiple domains forwarding to the same backend.
func TestDomainForwardMultipleSameTarget(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "host=%s", r.Host)
	}))
	defer backend.Close()

	ts, server := startTunnelServer(t)
	defer ts.Close()

	proxyPort := freePort(t)
	if err := server.StartProxy(fmt.Sprintf("127.0.0.1:%d", proxyPort)); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	client := vtunnel.NewClient(wsURL(ts))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	target := backend.Listener.Addr().String()
	client.Forward("a.test", target)
	client.Forward("b.test", target)
	client.Forward("c.test", target)
	time.Sleep(200 * time.Millisecond)

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	httpClient := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	for _, domain := range []string{"a.test", "b.test", "c.test"} {
		resp, err := httpClient.Get(fmt.Sprintf("http://%s/", domain))
		if err != nil {
			t.Fatalf("GET %s: %v", domain, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(body), "host=") {
			t.Fatalf("unexpected body for %s: %q", domain, body)
		}
		t.Logf("%s -> %s", domain, body)
	}
}

// TestDomainForwardReconnect tests that domain forwards survive client reconnection.
func TestDomainForwardReconnect(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "reconnect-ok")
	}))
	defer backend.Close()

	server := vtunnel.NewServer()
	proxyPort := freePort(t)
	if err := server.StartProxy(fmt.Sprintf("127.0.0.1:%d", proxyPort)); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	tunnelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		server.HandleConn(conn)
	}))
	defer tunnelServer.Close()

	client := vtunnel.NewClient(wsURL(tunnelServer),
		vtunnel.WithReconnectBackoff(100*time.Millisecond, 200*time.Millisecond),
	)
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	if err := client.Forward("recon.test", backend.Listener.Addr().String()); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Verify it works before reconnect
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	httpClient := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp, err := httpClient.Get("http://recon.test/")
	if err != nil {
		t.Fatalf("pre-reconnect GET: %v", err)
	}
	resp.Body.Close()

	// Force reconnect by closing the underlying WebSocket server briefly
	tunnelServer.CloseClientConnections()
	time.Sleep(500 * time.Millisecond) // wait for reconnect

	// Verify it works after reconnect
	resp, err = httpClient.Get("http://recon.test/")
	if err != nil {
		t.Fatalf("post-reconnect GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "reconnect-ok" {
		t.Fatalf("expected 'reconnect-ok', got %q", body)
	}
	t.Log("Domain forward survived reconnect")
}

// TestDomainForwardSameDomainTargetWithMitm tests that when MITM CA is configured,
// forwarding to a TLS target (e.g. google.com:443 → google.com:443) works via
// MITM + auto tls:// on the client side.
func TestDomainForwardSameDomainTargetWithMitm(t *testing.T) {
	ca := generateTestCA(t)
	server := vtunnel.NewServer(vtunnel.WithProxyMitmCA(ca))

	proxyPort := freePort(t)
	if err := server.StartProxy(fmt.Sprintf("127.0.0.1:%d", proxyPort)); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	tunnelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		server.HandleConn(conn)
	}))
	defer tunnelServer.Close()

	client := vtunnel.NewClient(wsURL(tunnelServer))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	if err := client.Forward("google.com:443", "google.com:443"); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := httpClient.Get("https://google.com/")
	if err != nil {
		t.Fatalf("GET https://google.com via tunnel with MITM: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	t.Logf("https://google.com with MITM CA -> %d (passthrough expected)", resp.StatusCode)
}
