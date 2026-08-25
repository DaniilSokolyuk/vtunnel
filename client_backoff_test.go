package vtunnel

// Backoff, and what counts as a connection worth resetting it for.

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// newBackoff built the object and then set its fields, which is one step too
// late: backoff.NewExponentialBackOff resets itself before returning, freezing
// the current interval at the package default of 500ms. Assigning
// InitialInterval afterwards changed a field nothing read again until the next
// Reset — and connectionLoop only resets after a *successful* reconnect. So the
// first series of retries, the one that matters, ignored WithReconnectBackoff
// entirely.
func TestBackoffStartsAtTheConfiguredMinimum(t *testing.T) {
	c := &Client{reconnectMin: 5 * time.Second, reconnectMax: 60 * time.Second}

	if got := c.newBackoff().NextBackOff(); got != 5*time.Second {
		t.Fatalf("first backoff = %v, want the configured 5s", got)
	}
}

// A session that dies the moment it is made is not a reconnect, and treating it
// as one turns the reconnect loop into a spin: connect, die, connect, die, with
// no delay anywhere. An endpoint that accepts and immediately hangs up — a
// half-deployed sandbox, a proxy answering for one that is gone — is enough to
// pin a core.
func TestReconnectDoesNotSpinOnSessionsThatDieAtOnce(t *testing.T) {
	var dials atomic.Int32

	client := NewClient("tcp://in-memory",
		WithProtocol(ProtocolYamuxInsecure), WithKeepAlive(-1),
		WithReconnectBackoff(20*time.Millisecond, 200*time.Millisecond))
	client.dialer = func(context.Context) (net.Conn, error) {
		dials.Add(1)
		// Accepted, and gone: the session comes up over a connection whose far
		// end is already closed.
		ours, theirs := net.Pipe()
		theirs.Close()
		return ours, nil
	}
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	time.Sleep(500 * time.Millisecond)

	// 500ms of 20ms-and-doubling backoff is a handful of attempts. Without any
	// backoff at all it is thousands.
	if n := dials.Load(); n > 20 {
		t.Fatalf("%d dials in half a second: the reconnect loop is spinning, because a "+
			"session that never carried anything reset the backoff", n)
	}
}

// The other half of the same rule: a session that did its job and then ended
// starts the next attempt from the configured minimum, not from wherever the
// last failure left the backoff.
func TestBackoffResetsAfterASessionThatLived(t *testing.T) {
	server := NewServer(WithServerProtocol(ProtocolYamuxInsecure), WithServerKeepAlive(-1))
	t.Cleanup(func() { server.Close() })

	var dials atomic.Int32
	client := NewClient("tcp://in-memory",
		WithProtocol(ProtocolYamuxInsecure), WithKeepAlive(-1),
		WithReconnectBackoff(10*time.Millisecond, 20*time.Millisecond))
	client.dialer = func(context.Context) (net.Conn, error) {
		dials.Add(1)
		serverSide, clientSide := net.Pipe()
		go server.HandleConn(serverSide)
		return clientSide, nil
	}
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	// A session that lives longer than the longest backoff is a real one.
	time.Sleep(60 * time.Millisecond)
	client.getSession().Close()

	waitUntil(t, 3*time.Second, "the client to reconnect", func() bool {
		return dials.Load() >= 2 && client.getSession() != nil
	})
}
