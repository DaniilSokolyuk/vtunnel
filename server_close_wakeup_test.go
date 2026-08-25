package vtunnel

// Two ways Close can be told the truth and still not be true: a connection
// parked waiting for a tunnel that will never come back, and a forwarded port
// registered a moment too late to be in the set Close emptied.

import (
	"net"
	"strconv"
	"testing"
	"time"
)

// A connection accepted on a forwarded port while the tunnel is down waits for
// the client to return. Close makes that wait provably pointless — nothing may
// publish a session afterwards — but it did not end it, so the socket, its
// goroutine and its descriptor outlived Close by the whole session timeout.
func spareTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestServerCloseWakesConnectionsWaitingForATunnel(t *testing.T) {
	client, server := connectedPair(t)

	port := spareTCPPort(t)
	if err := client.Listen(port, "127.0.0.1:1"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	waitUntil(t, 3*time.Second, "the forwarded port to open", func() bool {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	})

	// Take the tunnel away, then knock on the forwarded port: this connection
	// is now waiting for a session.
	client.Close()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial the forwarded port: %v", err)
	}
	defer conn.Close()
	time.Sleep(100 * time.Millisecond)

	start := time.Now()
	server.Close()

	conn.SetReadDeadline(time.Now().Add(6 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatalf("the connection was still parked %v after Close: it waits out "+
				"sessionWaitTimeout (%v) for a session Close has already made impossible",
				time.Since(start), sessionWaitTimeout)
		}
	}
}

// handleListen read the closed flag outside the mutex Close empties the
// listener map under. A request that passed the check just before Close took
// the lock registered its listener into a map already emptied, and started an
// accept loop nothing would ever stop.
//
// The window is a few instructions wide, so this is a guard rather than a
// reproduction: it is here to fail under -race and to catch the check drifting
// back out of the lock, not to demonstrate the original bug.
func TestListenRacingCloseLeavesNoListener(t *testing.T) {
	for range 200 {
		s := NewServer()
		done := make(chan struct{})
		go func() {
			defer close(done)
			left, right := net.Pipe()
			defer left.Close()
			go func() {
				buf := make([]byte, 256)
				for {
					if _, err := right.Read(buf); err != nil {
						return
					}
				}
			}()
			s.handleListen(left, streamHeader{Type: streamListen, Port: spareTCPPort(t)})
		}()
		s.Close()
		<-done

		s.listenersMu.Lock()
		n := len(s.listeners)
		s.listenersMu.Unlock()
		if n != 0 {
			t.Fatalf("%d listener(s) survived Close", n)
		}
	}
}
