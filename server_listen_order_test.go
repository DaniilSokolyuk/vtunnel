package vtunnel

// Two things about how a listen request is answered.

import (
	"net"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel/internal/session"
)

// The reply is what starts the client: it publishes the tunnel port and lets
// traffic flow. Sending it before the routes were installed left a window in
// which an application inside the sandbox could ask for a domain whose route
// had been promised but not yet set — and a miss in the router is not an error,
// it is direct egress, past the tunnel and past the credential.
//
// Checked at the moment of the write rather than after it, because after it the
// race is over and everything looks fine.
func TestListenRepliesOnlyOnceTheRoutesAreLive(t *testing.T) {
	server := NewServer()
	t.Cleanup(func() { server.Close() })

	var routedAtReply bool
	stream := &hookedStream{onWrite: func() {
		_, routedAtReply = server.router.route("api.corp:443")
	}}

	server.handleListen(stream, streamHeader{Type: streamListen, Domains: []string{"api.corp"}})

	if !stream.written {
		t.Fatal("handleListen never answered")
	}
	if !routedAtReply {
		t.Fatal("the reply went out before the route was installed: for that window the " +
			"sandbox sends the domain straight out, past the tunnel and past the credential")
	}
}

// A second client with the same secret used to displace the first without a
// word. Displacing is the right behaviour — a client that reconnects after a
// half-open connection must not be locked out by its own ghost, which a refusal
// would do for as long as the keepalive takes to notice — but it is worth
// saying out loud, and the old session has to actually go.
func TestSecondClientTakesOverAndTheFirstIsClosed(t *testing.T) {
	server := NewServer(WithServerProtocol(ProtocolYamuxInsecure), WithServerKeepAlive(-1))
	t.Cleanup(func() { server.Close() })

	first, firstClient := net.Pipe()
	go server.HandleConn(first)
	firstSess := dialInsecureSession(t, firstClient)
	waitUntil(t, 3*time.Second, "the first client to be published", func() bool {
		return activeSession(server) != nil
	})

	second, secondClient := net.Pipe()
	go server.HandleConn(second)
	secondSess := dialInsecureSession(t, secondClient)
	defer secondSess.Close()

	// The first session must end rather than linger: its streams would be
	// answered by a server that has moved on.
	done := make(chan struct{})
	go func() { firstSess.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the displaced client's session is still live; two clients are being served at once")
	}

	// And the newcomer is the one being served: its control streams are
	// answered, which is the only thing "being served" means here.
	if _, err := request(secondSess, streamHeader{Type: streamPing}); err != nil {
		t.Fatalf("the second client is not being served: %v", err)
	}
	if activeSession(server) == nil {
		t.Fatal("the takeover left the server with no active session at all")
	}
}

// --- helpers ---

func activeSession(s *Server) session.Session {
	s.activeConnMu.RLock()
	defer s.activeConnMu.RUnlock()
	return s.activeConn
}

// dialInsecureSession brings up the client half of a session on an already
// connected pipe, standing in for a whole Client.
func dialInsecureSession(t *testing.T, conn net.Conn) session.Session {
	t.Helper()
	sess, err := session.Dial(session.KindYamuxInsecure, conn, session.Config{})
	if err != nil {
		t.Fatalf("dial session: %v", err)
	}
	return sess
}

// hookedStream is a net.Conn that only exists to be written to, and to say when.
type hookedStream struct {
	net.Conn
	onWrite func()
	written bool
}

func (s *hookedStream) Write(p []byte) (int, error) {
	if s.onWrite != nil {
		s.onWrite()
	}
	s.written = true
	return len(p), nil
}

func (s *hookedStream) Close() error { return nil }
