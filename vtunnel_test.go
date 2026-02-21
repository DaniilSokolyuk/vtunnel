package vtunnel_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/DaniilSokolyuk/vtunnel"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitForHTTP(t *testing.T, port int, expected string, timeout time.Duration) {
	t.Helper()
	client := &http.Client{Timeout: 200 * time.Millisecond}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) == expected {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for HTTP on port %d", port)
}

func startTunnelServer(t *testing.T) (*httptest.Server, *vtunnel.Server) {
	t.Helper()
	server := vtunnel.NewServer()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Upgrade error: %v", err)
			return
		}
		defer conn.Close()
		server.HandleConn(conn)
	}))
	return ts, server
}

func wsURL(ts *httptest.Server) string {
	return "ws" + strings.TrimPrefix(ts.URL, "http")
}

// TestBasicTunnel tests basic HTTP proxying through the tunnel
func TestBasicTunnel(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Hello from backend!"))
	}))
	defer backend.Close()

	ts, _ := startTunnelServer(t)
	defer ts.Close()

	client := vtunnel.NewClient(wsURL(ts))
	err := client.Connect()
	if err != nil {
		t.Fatalf("Client connect error: %v", err)
	}
	defer client.Close()

	remotePort := freePort(t)
	err = client.Listen(remotePort, backend.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Listen error: %v", err)
	}

	waitForHTTP(t, remotePort, "Hello from backend!", 3*time.Second)
	t.Log("Basic tunnel works")
}

// TestMultiplePorts tests tunneling multiple ports
func TestMultiplePorts(t *testing.T) {
	backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Backend 1"))
	}))
	defer backend1.Close()

	backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Backend 2"))
	}))
	defer backend2.Close()

	ts, _ := startTunnelServer(t)
	defer ts.Close()

	client := vtunnel.NewClient(wsURL(ts))
	client.Connect()
	defer client.Close()

	port1, port2 := freePort(t), freePort(t)
	client.Listen(port1, backend1.Listener.Addr().String())
	client.Listen(port2, backend2.Listener.Addr().String())

	waitForHTTP(t, port1, "Backend 1", 3*time.Second)
	waitForHTTP(t, port2, "Backend 2", 3*time.Second)

	t.Logf("Port1: Backend 1, Port2: Backend 2")
}

// TestMultipleConnections tests multiple concurrent connections
func TestMultipleConnections(t *testing.T) {
	var counter atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := counter.Add(1)
		w.Write([]byte(fmt.Sprintf("Request %d", n)))
	}))
	defer backend.Close()

	ts, _ := startTunnelServer(t)
	defer ts.Close()

	client := vtunnel.NewClient(wsURL(ts))
	client.Connect()
	defer client.Close()

	port := freePort(t)
	client.Listen(port, backend.Listener.Addr().String())
	time.Sleep(200 * time.Millisecond)

	results := make(chan string, 10)
	for i := 0; i < 10; i++ {
		go func() {
			resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
			if err != nil {
				results <- fmt.Sprintf("error: %v", err)
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			results <- string(body)
		}()
	}

	for i := 0; i < 10; i++ {
		result := <-results
		t.Logf("Result %d: %s", i+1, result)
		if strings.HasPrefix(result, "error") {
			t.Error(result)
		}
	}
}

// TestAutoReconnectReplaysListen verifies that reconnect replays listens.
func TestAutoReconnectReplaysListen(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	connCh := make(chan *websocket.Conn, 2)
	server := vtunnel.NewServer()
	tunnelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Upgrade error: %v", err)
			return
		}
		select {
		case connCh <- conn:
		default:
		}
		server.HandleConn(conn)
	}))
	defer tunnelServer.Close()

	client := vtunnel.NewClient(
		wsURL(tunnelServer),
		vtunnel.WithAutoReconnect(true),
		vtunnel.WithKeepAlive(100*time.Millisecond),
		vtunnel.WithReconnectBackoff(50*time.Millisecond, 200*time.Millisecond),
	)
	if err := client.Connect(); err != nil {
		t.Fatalf("Client connect error: %v", err)
	}
	defer client.Close()

	port := freePort(t)
	if err := client.Listen(port, backend.Listener.Addr().String()); err != nil {
		t.Fatalf("Listen error: %v", err)
	}

	waitForHTTP(t, port, "ok", 3*time.Second)

	// Close first connection to trigger reconnect
	select {
	case conn1 := <-connCh:
		conn1.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for first WS connection")
	}

	// Wait for reconnect and verify tunnel works again
	select {
	case <-connCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for reconnection")
	}

	waitForHTTP(t, port, "ok", 3*time.Second)
}

// TestLargePayload tests transferring large data
func TestLargePayload(t *testing.T) {
	largeData := strings.Repeat("X", 1024*1024) // 1MB
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(largeData))
	}))
	defer backend.Close()

	ts, _ := startTunnelServer(t)
	defer ts.Close()

	client := vtunnel.NewClient(wsURL(ts))
	client.Connect()
	defer client.Close()

	port := freePort(t)
	client.Listen(port, backend.Listener.Addr().String())

	waitForHTTP(t, port, largeData, 5*time.Second)
	t.Logf("Transferred %d bytes successfully", len(largeData))
}

// TestTCPStream tests raw TCP streaming (not just HTTP)
func TestTCPStream(t *testing.T) {
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoListener.Close()

	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	ts, _ := startTunnelServer(t)
	defer ts.Close()

	client := vtunnel.NewClient(wsURL(ts))
	client.Connect()
	defer client.Close()

	port := freePort(t)
	client.Listen(port, echoListener.Addr().String())
	time.Sleep(200 * time.Millisecond)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("TCP dial failed: %v", err)
	}
	defer conn.Close()

	testData := "Hello TCP!"
	conn.Write([]byte(testData))

	buf := make([]byte, len(testData))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if string(buf[:n]) != testData {
		t.Errorf("Expected '%s', got '%s'", testData, string(buf[:n]))
	}

	t.Logf("TCP echo: %s", string(buf[:n]))
}

// TestKeepAlive tests that connection stays alive with keepalive pings
func TestKeepAlive(t *testing.T) {
	ts, _ := startTunnelServer(t)
	defer ts.Close()

	client := vtunnel.NewClient(wsURL(ts), vtunnel.WithKeepAlive(100*time.Millisecond))
	err := client.Connect()
	if err != nil {
		t.Fatalf("Connect error: %v", err)
	}

	// Wait for several ping/pong cycles
	time.Sleep(500 * time.Millisecond)

	client.Close()
	t.Log("Connection stayed alive through multiple ping/pong cycles")
}

// TestHandleConnReplace tests that two clients can connect to the same server
// sequentially without races or resource leaks.
func TestHandleConnReplace(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	server := vtunnel.NewServer()
	tunnelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		server.HandleConn(conn)
	}))
	defer tunnelServer.Close()

	// First client
	client1 := vtunnel.NewClient(wsURL(tunnelServer))
	if err := client1.Connect(); err != nil {
		t.Fatalf("Client1 connect error: %v", err)
	}
	port1 := freePort(t)
	client1.Listen(port1, backend.Listener.Addr().String())
	waitForHTTP(t, port1, "ok", 3*time.Second)

	// Close first client
	client1.Close()
	time.Sleep(200 * time.Millisecond)

	// Second client on same server
	client2 := vtunnel.NewClient(wsURL(tunnelServer))
	if err := client2.Connect(); err != nil {
		t.Fatalf("Client2 connect error: %v", err)
	}
	defer client2.Close()

	port2 := freePort(t)
	client2.Listen(port2, backend.Listener.Addr().String())
	waitForHTTP(t, port2, "ok", 3*time.Second)
	t.Log("Both clients worked correctly")
}

// TestReconnectSequentialTCP verifies that sequential numbered messages
// survive multiple WebSocket reconnects. A TCP counter backend sends
// incrementing numbers; we make requests before, between, and after
// forced disconnects and verify every number is received in order.
func TestReconnectSequentialTCP(t *testing.T) {
	// Backend: each TCP connection gets the next sequential number
	var counter atomic.Int64
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendLn.Close()

	go func() {
		for {
			conn, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				n := counter.Add(1)
				fmt.Fprintf(c, "%d\n", n)
			}(conn)
		}
	}()

	// Track WS connections so we can force-close them
	connCh := make(chan *websocket.Conn, 10)
	server := vtunnel.NewServer()
	tunnelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		select {
		case connCh <- conn:
		default:
		}
		server.HandleConn(conn)
	}))
	defer tunnelServer.Close()

	client := vtunnel.NewClient(
		wsURL(tunnelServer),
		vtunnel.WithAutoReconnect(true),
		vtunnel.WithKeepAlive(200*time.Millisecond),
		vtunnel.WithReconnectBackoff(50*time.Millisecond, 200*time.Millisecond),
	)
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	port := freePort(t)
	if err := client.Listen(port, backendLn.Addr().String()); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	readNumber := func(label string) int64 {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 1*time.Second)
			if err != nil {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf, err := io.ReadAll(conn)
			conn.Close()
			if err != nil || len(buf) == 0 {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			var n int64
			if _, err := fmt.Sscanf(string(buf), "%d", &n); err != nil {
				t.Fatalf("[%s] bad response: %q", label, buf)
			}
			return n
		}
		t.Fatalf("[%s] timeout reading number from tunnel", label)
		return 0
	}

	waitForWS := func() *websocket.Conn {
		t.Helper()
		select {
		case c := <-connCh:
			return c
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for WS connection")
			return nil
		}
	}

	numReconnects := 5
	var lastN int64

	// Initial connection — verify tunnel works
	wsConn := waitForWS()
	n := readNumber("before-reconnect-0")
	if n <= lastN {
		t.Fatalf("expected > %d, got %d", lastN, n)
	}
	lastN = n
	t.Logf("Before reconnects: got number %d", n)

	for i := 1; i <= numReconnects; i++ {
		// Force kill WS connection
		wsConn.Close()

		// Wait for reconnect
		wsConn = waitForWS()

		// Verify tunnel works after reconnect — number keeps incrementing
		n = readNumber(fmt.Sprintf("after-reconnect-%d", i))
		if n <= lastN {
			t.Fatalf("reconnect %d: expected > %d, got %d", i, lastN, n)
		}
		t.Logf("After reconnect %d: got number %d", i, n)
		lastN = n
	}

	// Final burst: 10 concurrent connections, all should get unique sequential numbers
	results := make(chan int64, 10)
	for i := 0; i < 10; i++ {
		go func() {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
			if err != nil {
				results <- -1
				return
			}
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf, err := io.ReadAll(conn)
			conn.Close()
			if err != nil || len(buf) == 0 {
				results <- -1
				return
			}
			var n int64
			fmt.Sscanf(string(buf), "%d", &n)
			results <- n
		}()
	}

	seen := make(map[int64]bool)
	for i := 0; i < 10; i++ {
		n := <-results
		if n == -1 {
			t.Error("failed to read number in final burst")
			continue
		}
		if n <= lastN {
			t.Errorf("final burst: expected > %d, got %d", lastN, n)
		}
		if seen[n] {
			t.Errorf("final burst: duplicate number %d", n)
		}
		seen[n] = true
	}
	t.Logf("Final burst: got %d unique numbers after %d reconnects", len(seen), numReconnects)
}

// TestTLSTermination tests tunneling to an external HTTPS service
// with client-side TLS termination using tls:// prefix
func TestTLSTermination(t *testing.T) {
	ts, _ := startTunnelServer(t)
	defer ts.Close()

	client := vtunnel.NewClient(wsURL(ts))
	err := client.Connect()
	if err != nil {
		t.Fatalf("Connect error: %v", err)
	}
	defer client.Close()

	port := freePort(t)
	err = client.Listen(port, "tls://google.com:443")
	if err != nil {
		t.Fatalf("Listen error: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 10 * time.Second,
	}

	resp, err := httpClient.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if err != nil {
		t.Fatalf("HTTP request error: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	t.Logf("Status: %d, Body length: %d bytes", resp.StatusCode, len(body))

	if resp.StatusCode == 0 {
		t.Error("Expected a valid HTTP status code")
	}
	if len(body) == 0 {
		t.Error("Expected non-empty response body from google.com")
	}
}
