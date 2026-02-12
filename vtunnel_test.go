package vtunnel_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/DaniilSokolyuk/vtunnel"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// TestBasicTunnel tests basic HTTP proxying through the tunnel
func TestBasicTunnel(t *testing.T) {
	// 1. Start a backend HTTP server (simulates LLM Proxy)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Hello from backend!"))
	}))
	defer backend.Close()

	// Extract backend port
	backendAddr := backend.Listener.Addr().String()
	t.Logf("Backend running at %s", backendAddr)

	// 2. Start vtunnel server (WebSocket)
	tunnelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Upgrade error: %v", err)
			return
		}
		defer conn.Close()

		server := vtunnel.NewServer()
		server.HandleConn(conn)
	}))
	defer tunnelServer.Close()

	// Convert http:// to ws://
	wsURL := "ws" + strings.TrimPrefix(tunnelServer.URL, "http")
	t.Logf("Tunnel server running at %s", wsURL)

	// 3. Connect vtunnel client
	client := vtunnel.NewClient(wsURL)
	err := client.Connect()
	if err != nil {
		t.Fatalf("Client connect error: %v", err)
	}
	defer client.Close()

	// 4. Request tunnel: remote port 18081 -> backend
	remotePort := 18081
	err = client.Listen(remotePort, backendAddr)
	if err != nil {
		t.Fatalf("Listen error: %v", err)
	}

	// Wait for listener to be established
	time.Sleep(100 * time.Millisecond)

	// 5. Make HTTP request through the tunnel
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/test", remotePort))
	if err != nil {
		t.Fatalf("HTTP request error: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "Hello from backend!" {
		t.Errorf("Expected 'Hello from backend!', got '%s'", string(body))
	}

	t.Logf("Response: %s", string(body))
}

// TestMultiplePorts tests tunneling multiple ports
func TestMultiplePorts(t *testing.T) {
	// Backend 1
	backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Backend 1"))
	}))
	defer backend1.Close()

	// Backend 2
	backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Backend 2"))
	}))
	defer backend2.Close()

	// Tunnel server
	tunnelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _ := upgrader.Upgrade(w, r, nil)
		defer conn.Close()
		server := vtunnel.NewServer()
		server.HandleConn(conn)
	}))
	defer tunnelServer.Close()

	wsURL := "ws" + strings.TrimPrefix(tunnelServer.URL, "http")

	// Connect client
	client := vtunnel.NewClient(wsURL)
	client.Connect()
	defer client.Close()

	// Listen on two ports
	port1, port2 := 18082, 18083
	client.Listen(port1, backend1.Listener.Addr().String())
	client.Listen(port2, backend2.Listener.Addr().String())

	time.Sleep(100 * time.Millisecond)

	// Test port 1
	resp1, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port1))
	if err != nil {
		t.Fatalf("Request to port1 failed: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()

	if string(body1) != "Backend 1" {
		t.Errorf("Port1: expected 'Backend 1', got '%s'", string(body1))
	}

	// Test port 2
	resp2, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port2))
	if err != nil {
		t.Fatalf("Request to port2 failed: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if string(body2) != "Backend 2" {
		t.Errorf("Port2: expected 'Backend 2', got '%s'", string(body2))
	}

	t.Logf("Port1: %s, Port2: %s", string(body1), string(body2))
}

// TestMultipleConnections tests multiple concurrent connections
func TestMultipleConnections(t *testing.T) {
	// Backend that echoes request number
	var counter int
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counter++
		w.Write([]byte(fmt.Sprintf("Request %d", counter)))
	}))
	defer backend.Close()

	// Tunnel server
	tunnelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _ := upgrader.Upgrade(w, r, nil)
		defer conn.Close()
		server := vtunnel.NewServer()
		server.HandleConn(conn)
	}))
	defer tunnelServer.Close()

	wsURL := "ws" + strings.TrimPrefix(tunnelServer.URL, "http")

	client := vtunnel.NewClient(wsURL)
	client.Connect()
	defer client.Close()

	port := 18084
	client.Listen(port, backend.Listener.Addr().String())
	time.Sleep(100 * time.Millisecond)

	// Make 10 concurrent requests
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

	// Collect results
	for i := 0; i < 10; i++ {
		result := <-results
		t.Logf("Result %d: %s", i+1, result)
		if strings.HasPrefix(result, "error") {
			t.Error(result)
		}
	}
}

// TestLargePayload tests transferring large data
func TestLargePayload(t *testing.T) {
	// Backend that returns large response
	largeData := strings.Repeat("X", 1024*1024) // 1MB
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(largeData))
	}))
	defer backend.Close()

	tunnelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _ := upgrader.Upgrade(w, r, nil)
		defer conn.Close()
		server := vtunnel.NewServer()
		server.HandleConn(conn)
	}))
	defer tunnelServer.Close()

	wsURL := "ws" + strings.TrimPrefix(tunnelServer.URL, "http")

	client := vtunnel.NewClient(wsURL)
	client.Connect()
	defer client.Close()

	port := 18085
	client.Listen(port, backend.Listener.Addr().String())
	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if len(body) != len(largeData) {
		t.Errorf("Expected %d bytes, got %d", len(largeData), len(body))
	}

	t.Logf("Transferred %d bytes successfully", len(body))
}

// TestTCPStream tests raw TCP streaming (not just HTTP)
func TestTCPStream(t *testing.T) {
	// Simple TCP echo server
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
				io.Copy(c, c) // Echo back
			}(conn)
		}
	}()

	// Tunnel server
	tunnelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _ := upgrader.Upgrade(w, r, nil)
		defer conn.Close()
		server := vtunnel.NewServer()
		server.HandleConn(conn)
	}))
	defer tunnelServer.Close()

	wsURL := "ws" + strings.TrimPrefix(tunnelServer.URL, "http")

	client := vtunnel.NewClient(wsURL)
	client.Connect()
	defer client.Close()

	port := 18086
	client.Listen(port, echoListener.Addr().String())
	time.Sleep(100 * time.Millisecond)

	// Connect via TCP
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("TCP dial failed: %v", err)
	}
	defer conn.Close()

	// Send data
	testData := "Hello TCP!"
	conn.Write([]byte(testData))

	// Read echo
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

// TestPingPong tests that ping/pong keepalive works
func TestPingPong(t *testing.T) {
	var pingReceived, pongSent int
	var mu sync.Mutex
	done := make(chan struct{})

	// Simple WebSocket server that tracks pings
	tunnelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Upgrade error: %v", err)
			return
		}
		defer conn.Close()

		// Track ping frames
		conn.SetPingHandler(func(data string) error {
			mu.Lock()
			pingReceived++
			mu.Unlock()
			// Send pong back
			err := conn.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(time.Second))
			if err == nil {
				mu.Lock()
				pongSent++
				mu.Unlock()
			}
			return err
		})

		// Just read messages to keep connection alive
		for {
			select {
			case <-done:
				return
			default:
			}
			conn.SetReadDeadline(time.Now().Add(time.Second))
			if _, _, err := conn.ReadMessage(); err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					// Ignore timeout errors
					if !strings.Contains(err.Error(), "timeout") {
						return
					}
				}
			}
		}
	}))
	defer tunnelServer.Close()

	wsURL := "ws" + strings.TrimPrefix(tunnelServer.URL, "http")

	// Connect with short ping interval for testing
	client := vtunnel.NewClient(wsURL, vtunnel.WithPingInterval(100*time.Millisecond))
	err := client.Connect()
	if err != nil {
		t.Fatalf("Connect error: %v", err)
	}

	// Wait for several pings
	time.Sleep(350 * time.Millisecond)

	close(done)
	client.Close()

	mu.Lock()
	pings := pingReceived
	pongs := pongSent
	mu.Unlock()

	t.Logf("Pings received: %d, Pongs sent: %d", pings, pongs)

	if pings < 2 {
		t.Errorf("Expected at least 2 pings, got %d", pings)
	}
	if pongs < 2 {
		t.Errorf("Expected at least 2 pongs, got %d", pongs)
	}
}

// TestDisabledPing tests that ping can be disabled
func TestDisabledPing(t *testing.T) {
	var pingReceived int
	var mu sync.Mutex
	done := make(chan struct{})

	tunnelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		conn.SetPingHandler(func(string) error {
			mu.Lock()
			pingReceived++
			mu.Unlock()
			return nil
		})

		// Just read messages
		for {
			select {
			case <-done:
				return
			default:
			}
			conn.SetReadDeadline(time.Now().Add(time.Second))
			conn.ReadMessage()
		}
	}))
	defer tunnelServer.Close()

	wsURL := "ws" + strings.TrimPrefix(tunnelServer.URL, "http")

	// Connect with ping disabled (negative value)
	client := vtunnel.NewClient(wsURL, vtunnel.WithPingInterval(-1))
	err := client.Connect()
	if err != nil {
		t.Fatalf("Connect error: %v", err)
	}

	// Wait a bit
	time.Sleep(200 * time.Millisecond)

	close(done)
	client.Close()

	mu.Lock()
	pings := pingReceived
	mu.Unlock()

	if pings != 0 {
		t.Errorf("Expected 0 pings with disabled ping, got %d", pings)
	}

	t.Logf("Pings with disabled mode: %d", pings)
}

// TestConnectionStaysAlive tests that connection stays alive for 20 seconds with ping/pong
func TestConnectionStaysAlive(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping long test in short mode")
	}

	var pingCount int
	var mu sync.Mutex
	connectionClosed := make(chan struct{})

	// Server that tracks pings and uses default pong handler
	tunnelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Upgrade error: %v", err)
			return
		}
		defer func() {
			conn.Close()
			close(connectionClosed)
		}()

		// Track pings, let default handler send pong
		conn.SetPingHandler(func(data string) error {
			mu.Lock()
			pingCount++
			count := pingCount
			mu.Unlock()
			t.Logf("Server received ping #%d", count)
			// Send pong (default behavior)
			return conn.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(time.Second))
		})

		// Read loop
		for {
			conn.SetReadDeadline(time.Now().Add(25 * time.Second))
			_, _, err := conn.ReadMessage()
			if err != nil {
				t.Logf("Server read error: %v", err)
				return
			}
		}
	}))
	defer tunnelServer.Close()

	wsURL := "ws" + strings.TrimPrefix(tunnelServer.URL, "http")

	// Connect with 2 second ping interval
	client := vtunnel.NewClient(wsURL, vtunnel.WithPingInterval(2*time.Second))
	err := client.Connect()
	if err != nil {
		t.Fatalf("Connect error: %v", err)
	}

	t.Log("Connection established, waiting 20 seconds...")

	// Wait 20 seconds
	select {
	case <-connectionClosed:
		t.Fatal("Connection closed unexpectedly!")
	case <-time.After(20 * time.Second):
		t.Log("20 seconds passed, connection still alive!")
	}

	client.Close()

	mu.Lock()
	pings := pingCount
	mu.Unlock()

	// Should have ~10 pings (20 sec / 2 sec interval)
	t.Logf("Total pings received: %d", pings)
	if pings < 8 {
		t.Errorf("Expected at least 8 pings in 20 seconds, got %d", pings)
	}
}

// TestTLSTermination tests tunneling to an external HTTPS service (google.com)
// with client-side TLS termination using tls:// prefix
func TestTLSTermination(t *testing.T) {
	// Tunnel server
	tunnelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _ := upgrader.Upgrade(w, r, nil)
		defer conn.Close()
		server := vtunnel.NewServer()
		server.HandleConn(conn)
	}))
	defer tunnelServer.Close()

	wsURL := "ws" + strings.TrimPrefix(tunnelServer.URL, "http")

	client := vtunnel.NewClient(wsURL)
	err := client.Connect()
	if err != nil {
		t.Fatalf("Connect error: %v", err)
	}
	defer client.Close()

	// Forward local port 18087 -> google.com:443 with TLS termination
	port := 18087
	err = client.Listen(port, "tls://google.com:443")
	if err != nil {
		t.Fatalf("Listen error: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Make plain HTTP request through tunnel — vtunnel client terminates TLS to google
	// Use a custom client to avoid redirect following and set Host header
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

	t.Logf("Status: %d", resp.StatusCode)
	t.Logf("Body length: %d bytes", len(body))

	if resp.StatusCode == 0 {
		t.Error("Expected a valid HTTP status code")
	}
	if len(body) == 0 {
		t.Error("Expected non-empty response body from google.com")
	}
}
