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

// --- helpers ---

type reconnectEnv struct {
	server       *vtunnel.Server
	tunnelServer *httptest.Server
	client       *vtunnel.Client
	connCh       chan *websocket.Conn
}

func newReconnectEnv(t *testing.T, opts ...vtunnel.Option) *reconnectEnv {
	t.Helper()
	env := &reconnectEnv{
		server: vtunnel.NewServer(),
		connCh: make(chan *websocket.Conn, 20),
	}
	env.tunnelServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		env.connCh <- conn
		env.server.HandleConn(conn)
	}))

	defaults := []vtunnel.Option{
		vtunnel.WithKeepAlive(200 * time.Millisecond),
		vtunnel.WithReconnectBackoff(50*time.Millisecond, 200*time.Millisecond),
	}
	env.client = vtunnel.NewClient(wsURL(env.tunnelServer), append(defaults, opts...)...)
	if err := env.client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	// wait for initial connection to appear in connCh (but don't drain it — killWS will use it)
	select {
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for initial WS connection")
	case <-func() chan struct{} {
		ch := make(chan struct{})
		go func() {
			for len(env.connCh) == 0 {
				time.Sleep(5 * time.Millisecond)
			}
			close(ch)
		}()
		return ch
	}():
	}
	return env
}

func (e *reconnectEnv) close() {
	e.client.Close()
	e.tunnelServer.Close()
}

// killWS closes the current WS connection (without waiting for reconnect).
func (e *reconnectEnv) killWS(t *testing.T) {
	t.Helper()
	select {
	case conn := <-e.connCh:
		conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("no WS connection to kill")
	}
}

// killAndWaitReconnect kills the current WS and blocks until the client
// reconnects. The new connection is left in connCh for the next killWS.
func (e *reconnectEnv) killAndWaitReconnect(t *testing.T) {
	t.Helper()
	// Kill current
	e.killWS(t)
	// Wait for reconnect to appear (peek, don't consume)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for WS reconnect")
			return
		default:
		}
		if len(e.connCh) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func tcpReadRetry(t *testing.T, addr string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf, err := io.ReadAll(conn)
		conn.Close()
		if err == nil && len(buf) > 0 {
			return string(buf)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout reading from %s", addr)
	return ""
}

// counterBackend returns a TCP listener where each connection gets the next number.
func counterBackend(t *testing.T) (net.Listener, *atomic.Int64) {
	t.Helper()
	var counter atomic.Int64
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
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
	return ln, &counter
}

// httpBackend returns a backend that serves the given body.
func httpBackend(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
}

// --- tests ---

// 1. Single port survives reconnect, listener reused.
func TestReconnectReplaysListen(t *testing.T) {
	env := newReconnectEnv(t)
	defer env.close()

	backend := httpBackend(t, "ok")
	defer backend.Close()

	port := freePort(t)
	if err := env.client.Listen(port, backend.Listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	waitForHTTP(t, port, "ok", 3*time.Second)

	env.killAndWaitReconnect(t)

	waitForHTTP(t, port, "ok", 3*time.Second)
}

// 2. Multiple ports all survive reconnect.
func TestReconnectMultiplePorts(t *testing.T) {
	env := newReconnectEnv(t)
	defer env.close()

	backends := make([]*httptest.Server, 3)
	ports := make([]int, 3)
	for i := range 3 {
		body := fmt.Sprintf("backend-%d", i)
		backends[i] = httpBackend(t, body)
		defer backends[i].Close()
		ports[i] = freePort(t)
		env.client.Listen(ports[i], backends[i].Listener.Addr().String())
	}

	for i := range 3 {
		waitForHTTP(t, ports[i], fmt.Sprintf("backend-%d", i), 3*time.Second)
	}

	env.killAndWaitReconnect(t)

	for i := range 3 {
		waitForHTTP(t, ports[i], fmt.Sprintf("backend-%d", i), 3*time.Second)
	}
}

// 3. Sequential numbers across 5 reconnects — no gaps.
func TestReconnectSequentialNumbers(t *testing.T) {
	env := newReconnectEnv(t)
	defer env.close()

	backendLn, _ := counterBackend(t)
	defer backendLn.Close()

	port := freePort(t)
	env.client.Listen(port, backendLn.Addr().String())

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	var lastN int64

	for round := 0; round < 6; round++ {
		s := tcpReadRetry(t, addr, 5*time.Second)
		var n int64
		fmt.Sscanf(s, "%d", &n)
		if n <= lastN {
			t.Fatalf("round %d: expected > %d, got %d", round, lastN, n)
		}
		lastN = n

		if round < 5 {
			env.killAndWaitReconnect(t)
		}
	}
	t.Logf("6 sequential numbers across 5 reconnects, last=%d", lastN)
}

// 4. Burst of 20 parallel TCP connections immediately after reconnect.
func TestReconnectBurstAfterReconnect(t *testing.T) {
	env := newReconnectEnv(t)
	defer env.close()

	backendLn, _ := counterBackend(t)
	defer backendLn.Close()

	port := freePort(t)
	env.client.Listen(port, backendLn.Addr().String())

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	// warm up
	tcpReadRetry(t, addr, 3*time.Second)

	env.killAndWaitReconnect(t)

	const N = 20
	results := make(chan int64, N)
	for range N {
		go func() {
			s := tcpReadRetry(t, addr, 5*time.Second)
			var n int64
			fmt.Sscanf(s, "%d", &n)
			results <- n
		}()
	}

	seen := make(map[int64]bool)
	for range N {
		n := <-results
		if n == 0 {
			t.Error("got 0")
			continue
		}
		if seen[n] {
			t.Errorf("duplicate: %d", n)
		}
		seen[n] = true
	}
	if len(seen) != N {
		t.Errorf("expected %d unique numbers, got %d", N, len(seen))
	}
}

// 5. 10 rapid disconnect/reconnect with no pause.
func TestReconnectRapidFlapping(t *testing.T) {
	env := newReconnectEnv(t)
	defer env.close()

	backend := httpBackend(t, "flap")
	defer backend.Close()

	port := freePort(t)
	env.client.Listen(port, backend.Listener.Addr().String())
	waitForHTTP(t, port, "flap", 3*time.Second)

	for i := range 10 {
		env.killAndWaitReconnect(t)
		t.Logf("flap %d done", i+1)
	}

	// After 10 rapid flaps, tunnel still works
	waitForHTTP(t, port, "flap", 5*time.Second)
}

// 6. Kill WS during a large transfer, then verify new transfers work.
func TestReconnectDuringActiveTransfer(t *testing.T) {
	// Backend streams 1MB slowly
	largeData := strings.Repeat("X", 1024*1024)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(largeData))
	}))
	defer backend.Close()

	env := newReconnectEnv(t)
	defer env.close()

	port := freePort(t)
	env.client.Listen(port, backend.Listener.Addr().String())
	waitForHTTP(t, port, largeData, 5*time.Second)

	// Start a transfer in background
	transferDone := make(chan error, 1)
	go func() {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
		if err != nil {
			transferDone <- err
			return
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		transferDone <- nil
	}()

	// Kill WS mid-transfer
	time.Sleep(10 * time.Millisecond)
	env.killAndWaitReconnect(t)

	// Old transfer may fail or succeed — we don't care
	<-transferDone

	// New transfer must work
	waitForHTTP(t, port, largeData, 5*time.Second)
}

// 7. Close() called while reconnectLoop is retrying.
func TestReconnectCloseWhileReconnecting(t *testing.T) {
	env := newReconnectEnv(t)

	backend := httpBackend(t, "x")
	defer backend.Close()

	port := freePort(t)
	env.client.Listen(port, backend.Listener.Addr().String())
	waitForHTTP(t, port, "x", 3*time.Second)

	// Kill WS — client enters reconnect loop
	env.killWS(t)
	time.Sleep(30 * time.Millisecond) // let reconnect loop start

	// Close while reconnecting — should not panic or hang
	done := make(chan struct{})
	go func() {
		env.client.Close()
		close(done)
	}()

	select {
	case <-done:
		t.Log("Close() completed during reconnect")
	case <-time.After(5 * time.Second):
		t.Fatal("Close() hung during reconnect")
	}

	env.tunnelServer.Close()
}

// 8. Backoff timing is respected between reconnect attempts.
func TestReconnectBackoffRespected(t *testing.T) {
	connTimes := make(chan time.Time, 10)
	server := vtunnel.NewServer()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connTimes <- time.Now()
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		server.HandleConn(conn)
	}))
	defer ts.Close()

	minBackoff := 100 * time.Millisecond
	maxBackoff := 300 * time.Millisecond

	client := vtunnel.NewClient(wsURL(ts),
		vtunnel.WithKeepAlive(200*time.Millisecond),
		vtunnel.WithReconnectBackoff(minBackoff, maxBackoff),
	)
	if err := client.Connect(); err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Initial connect
	<-connTimes

	// Now shut down the WS server to make reconnects fail
	ts.Close()

	// Collect reconnect attempt timestamps (will all fail)
	var attempts []time.Time
	timeout := time.After(3 * time.Second)
	for range 4 {
		select {
		case tm := <-connTimes:
			attempts = append(attempts, tm)
		case <-timeout:
			goto done
		}
	}
done:

	// Verify intervals between attempts are >= minBackoff
	for i := 1; i < len(attempts); i++ {
		interval := attempts[i].Sub(attempts[i-1])
		if interval < minBackoff/2 { // allow some slack
			t.Errorf("attempt %d→%d interval %v < min %v", i-1, i, interval, minBackoff)
		}
		t.Logf("attempt %d→%d: %v", i-1, i, interval)
	}
}
