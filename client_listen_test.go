package vtunnel

// What Client.Listen accepts.
//
// A raw forward is a port in the sandbox that something inside the sandbox is
// expected to connect to, which means the port has to be one the caller chose
// and can tell that something about. Asking the sandbox to pick is therefore
// not a feature with a missing return value — it is a request with no meaning.
//
// It used to be accepted anyway: the sandbox allocated an ephemeral port and
// reported it, sendListen dropped the answer, and the forward stayed filed
// under 0. Tunnel streams then arrived tagged with the real port, found nothing
// under it and were closed one by one ("No forward for port N") — while Listen
// had returned nil and the caller had every reason to believe the forward was
// up.

import (
	"context"
	"net"
	"strings"
	"testing"
)

// connectedPair wires a client to a server over an in-memory connection, with
// no transport, keepalive or cryptography in the way.
func connectedPair(t *testing.T) (*Client, *Server) {
	t.Helper()

	server := NewServer(WithServerProtocol(ProtocolYamuxInsecure), WithServerKeepAlive(-1))
	client := NewClient("tcp://in-memory",
		WithProtocol(ProtocolYamuxInsecure), WithKeepAlive(-1))

	serverSide, clientSide := net.Pipe()
	go server.HandleConn(serverSide)
	client.dialer = func(context.Context) (net.Conn, error) { return clientSide, nil }

	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client, server
}

func TestListenRefusesPortZero(t *testing.T) {
	client, server := connectedPair(t)

	err := client.Listen(0, "localhost:3000")
	if err == nil {
		t.Fatal("Listen(0, ...) reported success; the forward it set up can never receive " +
			"a connection, because the streams arrive tagged with the port the sandbox chose")
	}
	if !strings.Contains(err.Error(), "port") {
		t.Fatalf("err = %v, want it to name the port as the problem", err)
	}

	// Nothing was opened in the sandbox on the way to failing.
	server.listenersMu.Lock()
	opened := len(server.listeners)
	server.listenersMu.Unlock()
	if opened != 0 {
		t.Fatalf("the sandbox opened %d listener(s) for a request that was refused", opened)
	}

	// And nothing was left on the client either: a forward filed under 0 would
	// be replayed on every reconnect, failing the same way for as long as the
	// client lives.
	client.mu.RLock()
	_, kept := client.forwards[0]
	client.mu.RUnlock()
	if kept {
		t.Fatal("the refused forward stayed in c.forwards and will be replayed on every reconnect")
	}
}

// A port that cannot exist is refused on the same grounds, and before anything
// is sent.
func TestListenRefusesPortsOutOfRange(t *testing.T) {
	client, _ := connectedPair(t)

	for _, port := range []int{-1, 65536} {
		if err := client.Listen(port, "localhost:3000"); err == nil {
			t.Fatalf("Listen(%d, ...) was accepted", port)
		}
	}
}

// The ordinary case still works, and the forward is filed under the port the
// caller named.
func TestListenAcceptsAFixedPort(t *testing.T) {
	client, server := connectedPair(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // freed; the sandbox is about to take it

	if err := client.Listen(port, "localhost:3000"); err != nil {
		t.Fatalf("Listen(%d, ...): %v", port, err)
	}

	client.mu.RLock()
	addr := client.forwards[port]
	client.mu.RUnlock()
	if addr != "localhost:3000" {
		t.Fatalf("forwards[%d] = %q, want the local address", port, addr)
	}

	server.listenersMu.Lock()
	_, listening := server.listeners[port]
	server.listenersMu.Unlock()
	if !listening {
		t.Fatalf("the sandbox is not listening on %d", port)
	}
}
