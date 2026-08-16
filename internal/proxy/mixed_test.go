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

// flakyListener fails its first n Accepts with a temporary error, the way a
// listener does when the process is out of descriptors or a client hangs up
// between the SYN and the accept.
type flakyListener struct {
	net.Listener
	remaining int
}

type temporaryError struct{}

func (temporaryError) Error() string   { return "accept: too many open files" }
func (temporaryError) Timeout() bool   { return false }
func (temporaryError) Temporary() bool { return true }

func (l *flakyListener) Accept() (net.Conn, error) {
	if l.remaining > 0 {
		l.remaining--
		return nil, temporaryError{}
	}
	return l.Listener.Accept()
}

// A temporary Accept error is not the end of the listener. It used to be: the
// loop returned, and every later Accept blocked forever on channels nobody
// would ever write to again — so one burst of descriptor exhaustion, which any
// client can cause, took the sandbox proxy down until the process restarted.
// http.Server.Serve retries these for exactly this reason, and wrapping the
// listener took that away.
func TestTemporaryAcceptErrorDoesNotKillTheListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	m := NewMixed(&flakyListener{Listener: ln, remaining: 2}, time.Second, nil)
	defer m.Close()

	go func() {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
		time.Sleep(500 * time.Millisecond)
	}()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := m.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	select {
	case conn := <-accepted:
		conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("no connection was ever accepted: a temporary Accept error ended the loop, " +
			"and the listener is now permanently deaf")
	}
}

// A permanent error still ends it, and keeps saying so rather than blocking.
func TestPermanentAcceptErrorIsReportedRepeatedly(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := NewMixed(ln, time.Second, nil)
	ln.Close()

	for i := range 3 {
		done := make(chan error, 1)
		go func() {
			_, err := m.Accept()
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("Accept %d returned no error after the listener was closed", i)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("Accept %d blocked instead of reporting the closed listener", i)
		}
	}
	m.Close()
}
