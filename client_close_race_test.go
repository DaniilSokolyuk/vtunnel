package vtunnel

// Close while a reconnect is in flight.
//
// connectionLoop can be inside connectOnce when the owner calls Close: the dial
// was already under way, and it finishes afterwards. Nothing stopped it from
// publishing the session it had just made, so a client its owner considered
// closed went on holding a live tunnel — with the goroutines around it, and the
// loop that makes another one as soon as this one dies.

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientCloseStopsAnInFlightReconnect(t *testing.T) {
	server := NewServer(WithServerProtocol(ProtocolYamuxInsecure), WithServerKeepAlive(-1))
	t.Cleanup(func() { server.Close() })

	var dials atomic.Int32
	release := make(chan struct{})
	dialed := make(chan struct{}, 4)

	client := NewClient("tcp://in-memory",
		WithProtocol(ProtocolYamuxInsecure), WithKeepAlive(-1),
		WithReconnectBackoff(time.Millisecond, time.Millisecond))
	client.dialer = func(context.Context) (net.Conn, error) {
		// Every dial but the first parks until the test lets it through, which
		// is what puts Close and a half-finished reconnect in the same moment.
		if dials.Add(1) > 1 {
			<-release
		}
		serverSide, clientSide := net.Pipe()
		go server.HandleConn(serverSide)
		dialed <- struct{}{}
		return clientSide, nil
	}

	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	// Kill the first session so the loop goes for another one, and wait until
	// that dial is parked.
	client.getSession().Close()
	waitUntil(t, 3*time.Second, "the reconnect dial to start", func() bool {
		return dials.Load() >= 2
	})

	client.Close()
	close(release) // the reconnect completes now, after Close

	<-dialed // the first dial
	select {
	case <-dialed: // the parked one, now through
	case <-time.After(3 * time.Second):
		t.Fatal("the parked dial never completed")
	}
	time.Sleep(100 * time.Millisecond) // let connectOnce finish publishing, if it means to

	// Whatever that dial produced must not become this client's session.
	if sess := client.getSession(); sess != nil {
		t.Fatal("a reconnect that finished after Close published its session: " +
			"the closed client is holding a live tunnel")
	}

	// And the loop must be over: no further dials, ever.
	after := dials.Load()
	time.Sleep(200 * time.Millisecond)
	if now := dials.Load(); now != after {
		t.Fatalf("dials went %d -> %d after Close: the reconnect loop is still running", after, now)
	}
}

// The session made by that late reconnect must be closed, not merely dropped:
// an unpublished but live session is a tunnel nobody can reach and nobody
// closes.
func TestClientCloseClosesALateSession(t *testing.T) {
	server := NewServer(WithServerProtocol(ProtocolYamuxInsecure), WithServerKeepAlive(-1))
	t.Cleanup(func() { server.Close() })

	client := NewClient("tcp://in-memory", WithProtocol(ProtocolYamuxInsecure), WithKeepAlive(-1))
	serverSide, clientSide := net.Pipe()
	go server.HandleConn(serverSide)
	client.dialer = func(context.Context) (net.Conn, error) { return clientSide, nil }

	// Closed before anything is published: exactly the state a late connectOnce
	// finds itself in.
	client.Close()

	if err := client.connectOnce(); err == nil {
		if sess := client.getSession(); sess != nil {
			t.Fatal("connectOnce published a session on a closed client")
		}
	}

	done := make(chan struct{})
	go func() {
		serverSide.SetDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 1)
		serverSide.Read(buf) // returns once the client end is gone
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the session made after Close is still live")
	}
}

func waitUntil(t *testing.T, limit time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
