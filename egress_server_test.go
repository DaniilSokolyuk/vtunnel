package vtunnel

// The egress proxy's own HTTP server.
//
// It was started as `go http.Serve(ln, ...)`, which keeps no server around: no
// timeout could be set on it, Close could only shut the door and leave everyone
// already inside, and whatever Serve returned went nowhere. That matters more
// here than anywhere else in the tree — the egress proxy is the one listener that
// faces the sandbox's network, while the MITM proxy sits on loopback.

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A peer that connects and then says nothing must not cost a goroutine and a
// descriptor for the life of the process.
func TestEgressBoundsTheRequestHeader(t *testing.T) {
	prev := serverReadHeaderTimeout.Get()
	serverReadHeaderTimeout.Set(200 * time.Millisecond)
	t.Cleanup(func() { serverReadHeaderTimeout.Set(prev) })

	egress := newEgressProxy()
	if err := egress.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer egress.Close()

	conn, err := net.DialTimeout("tcp", egress.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial the egress proxy: %v", err)
	}
	defer conn.Close()

	// Enough to look like the beginning of a request, then silence.
	if _, err := conn.Write([]byte("GET / HTT")); err != nil {
		t.Fatalf("write: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatalf("read: %v", err)
	}
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Fatalf("the connection was still open after %v: the egress proxy has no header deadline", elapsed)
	}
}

// Close means closed: a live keep-alive connection is not something a caller
// can find and hang up on, so the egress proxy has to.
func TestEgressCloseEndsLiveConnections(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "backend")
	}))
	defer backend.Close()

	egress := newEgressProxy()
	if err := egress.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	conn, err := net.DialTimeout("tcp", egress.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial the egress proxy: %v", err)
	}
	defer conn.Close()

	// One ordinary proxied request, so the connection is established and idle
	// rather than merely accepted.
	req, _ := http.NewRequest(http.MethodGet, backend.URL+"/", nil)
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	egress.Close()

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("the connection survived Close: the egress proxy closed its listener and left " +
			"everyone already inside")
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("the connection was still open three seconds after Close")
	}
}

// Close before Start, twice over, and Start after Close: the same shapes the
// MITM proxy already refuses to fall over on, answered the same way.
//
// Start after Close is refused rather than honoured. Honouring it is what left
// a listener nothing could close: Close had already spent its guard on an egress proxy
// that had none, so the one installed afterwards outlived every later Close.
func TestEgressCloseIsIdempotent(t *testing.T) {
	egress := newEgressProxy()
	egress.Close()
	egress.Close()

	if err := egress.Start("127.0.0.1:0"); err == nil {
		t.Fatal("Start after Close was accepted")
	}

	fresh := newEgressProxy()
	if err := fresh.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := fresh.Addr().String()
	fresh.Close()
	fresh.Close()

	if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		conn.Close()
		t.Fatalf("%s is still accepting after Close", addr)
	}
}
