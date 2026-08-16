package vtunnel

// Shutting the sandbox end down.
//
// A Server owns things that deliberately outlive any single client connection:
// one listener and one accept loop per forwarded port, kept alive so a
// reconnecting client finds its ports still open. Nothing could end them. For a
// process that embeds vtunnel — or a test suite that starts a hundred servers —
// that is a listener, a goroutine and a descriptor per forward, leaked for the
// life of the process, with the ports still answering on behalf of a tunnel
// nobody is watching any more.

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestServerCloseReleasesForwardedPorts(t *testing.T) {
	client, server := connectedPair(t)

	port := freeTCPPort(t)
	if err := client.Listen(port, "localhost:1"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("the sandbox is not listening on the forwarded port: %v", err)
	}
	conn.Close()

	if err := server.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		conn.Close()
		t.Fatal("the forwarded port is still accepting connections after Server.Close")
	}

	server.listenersMu.Lock()
	left := len(server.listeners)
	server.listenersMu.Unlock()
	if left != 0 {
		t.Fatalf("%d listener(s) still registered after Close", left)
	}
}

// Close also ends the session it was serving, so the goroutines around it
// (stream loop, keepalive) come down with it rather than outliving the server.
func TestServerCloseEndsTheActiveSession(t *testing.T) {
	client, server := connectedPair(t)

	// Captured before the close: the client reconnects on its own, and what
	// this asserts is that the session the server was serving ends.
	sess := client.getSession()
	if sess == nil {
		t.Fatal("no session to begin with")
	}

	if err := server.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	done := make(chan struct{})
	go func() {
		sess.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the client's session is still live three seconds after the server closed")
	}
}

// After Close the server accepts no new work: a listen request is answered with
// an error rather than quietly opening a port on a server that is meant to be
// gone.
func TestServerRefusesListenAfterClose(t *testing.T) {
	client, server := connectedPair(t)

	if err := server.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	err := client.Listen(freeTCPPort(t), "localhost:1")
	if err == nil {
		t.Fatal("a closed server opened a new forwarded port")
	}
	if !strings.Contains(err.Error(), "closed") {
		t.Logf("err = %v", err) // any refusal will do; the wording is not the contract
	}
}

func TestServerCloseIsIdempotent(t *testing.T) {
	server := NewServer()
	if err := server.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// --- helpers ---

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
