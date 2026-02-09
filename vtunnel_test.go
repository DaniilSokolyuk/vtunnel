package vtunnel_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"vtunnel"
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
	client := vtunnel.NewClient()
	err := client.Connect(wsURL, nil)
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
	client := vtunnel.NewClient()
	client.Connect(wsURL, nil)
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

	client := vtunnel.NewClient()
	client.Connect(wsURL, nil)
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

	client := vtunnel.NewClient()
	client.Connect(wsURL, nil)
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

	client := vtunnel.NewClient()
	client.Connect(wsURL, nil)
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
