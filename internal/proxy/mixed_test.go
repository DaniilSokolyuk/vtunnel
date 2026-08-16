package proxy

// One port, both protocols.
//
// A sandbox points every runtime it has at one proxy: HTTP_PROXY and
// HTTPS_PROXY for anything that speaks HTTP, ALL_PROXY for everything that does
// not. Making that two ports means two firewall rules, two flags and two ways
// to get it wrong, so the listener tells the protocols apart itself — SOCKS5
// opens with its version byte, an HTTP request opens with a method. That is the
// same trick clash and sing-box call a "mixed" port.

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func tcpListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln
}

func TestMixedServesHTTPAndSocks5OnOnePort(t *testing.T) {
	var mu sync.Mutex
	var socksConns int

	mixed := NewMixed(tcpListener(t), time.Second, func(conn net.Conn) {
		defer conn.Close()
		mu.Lock()
		socksConns++
		mu.Unlock()
		// Answer the greeting and hang up; the point is only that this
		// connection arrived here rather than at the HTTP server.
		buf := make([]byte, 3)
		io.ReadFull(conn, buf)
		conn.Write([]byte{0x05, 0x00})
	})
	defer mixed.Close()

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "http here")
	})}
	go srv.Serve(mixed)
	defer srv.Close()

	addr := mixed.Addr().String()

	// HTTP first.
	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("HTTP through the mixed listener: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "http here" {
		t.Fatalf("body = %q, want %q", body, "http here")
	}

	// Then SOCKS5 on the very same port.
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if reply[0] != 0x05 {
		t.Fatalf("reply = % x: the SOCKS5 connection was served as HTTP", reply)
	}

	mu.Lock()
	defer mu.Unlock()
	if socksConns != 1 {
		t.Fatalf("the SOCKS5 handler saw %d connections, want 1", socksConns)
	}
}

// A connection that says nothing must not hold up the ones behind it, and must
// not cost a goroutine and a descriptor forever.
func TestMixedSilentConnectionDoesNotBlockOthers(t *testing.T) {
	mixed := NewMixed(tcpListener(t), 150*time.Millisecond, func(conn net.Conn) { conn.Close() })
	defer mixed.Close()

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})}
	go srv.Serve(mixed)
	defer srv.Close()

	addr := mixed.Addr().String()

	// Connects and says nothing at all.
	silent, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer silent.Close()

	// Someone else must still get served, immediately.
	done := make(chan string, 1)
	go func() {
		resp, err := http.Get("http://" + addr + "/")
		if err != nil {
			done <- "error: " + err.Error()
			return
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		done <- string(body)
	}()

	select {
	case got := <-done:
		if got != "ok" {
			t.Fatalf("second connection got %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a silent connection blocked the listener")
	}

	// And the silent one is hung up on once its deadline passes.
	silent.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := bufio.NewReader(silent).ReadByte(); err == nil {
		t.Fatal("the silent connection is still open")
	}
}

func TestMixedCloseStopsAccepting(t *testing.T) {
	mixed := NewMixed(tcpListener(t), time.Second, func(conn net.Conn) { conn.Close() })
	addr := mixed.Addr().String()

	accepted := make(chan error, 1)
	go func() {
		for {
			conn, err := mixed.Accept()
			if err != nil {
				accepted <- err
				return
			}
			conn.Close()
		}
	}()

	mixed.Close()

	select {
	case err := <-accepted:
		if err == nil {
			t.Fatal("Accept returned no error after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept is still blocked after Close")
	}

	if conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("the port is still open after Close")
	}
}
