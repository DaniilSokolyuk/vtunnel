package vtunnel

// The keepalive loop's own lifetime.
//
// It slept the whole interval before doing anything, so it outlived the session
// it was pinging by up to one interval — thirty seconds by default. Every
// closed client left one behind, holding a reference to a dead session and
// waking up to ping it.

import (
	"net"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel/internal/session"
)

func TestKeepAliveLoopEndsWithItsSession(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	server, err := session.Serve(session.KindYamuxInsecure, serverSide, session.Config{})
	if err != nil {
		t.Fatalf("serve session: %v", err)
	}
	defer server.Close()
	client, err := session.Dial(session.KindYamuxInsecure, clientSide, session.Config{})
	if err != nil {
		t.Fatalf("dial session: %v", err)
	}

	stopped := make(chan struct{})
	go func() {
		// An interval far longer than this test is willing to wait: what ends
		// the loop must be the session, not the clock.
		keepAliveLoop(client, time.Minute)
		close(stopped)
	}()

	client.Close()

	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("the keepalive loop is still running a session that is gone; it will keep " +
			"a closed client's goroutine alive for a whole interval")
	}
}
