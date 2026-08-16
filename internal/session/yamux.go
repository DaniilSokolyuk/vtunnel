package session

import (
	"fmt"
	"io"
	"net"

	"github.com/hashicorp/yamux"
)

// defaultMuxWindow is the per-stream receive window when Config says nothing.
//
// It is not yamux's own default, and not gost's — both leave it at 256 KB.
// Taking that would ship a backend slower than the one it exists to beat: a
// stream cannot exceed window/RTT, and SSH's hard-coded 2 MB would win by
// almost an order of magnitude on any link with latency. This is the smallest
// round number that is comfortably ahead of it instead.
//
// The figure is a ceiling on what may be in flight, not memory reserved: yamux
// grows recvBuf only while the local reader falls behind the tunnel, and the
// tunnel's reader is a copy loop that does not. The worst case is real, though
// — a stalled target can hold this much per connection — so it is a setting:
// Config.StreamWindow, reachable as WithStreamWindow and
// WithServerStreamWindow.
const defaultMuxWindow = 8 * 1024 * 1024

// conn arrives already authenticated and encrypted — see secureClient and
// secureServer. yamux itself brings no cryptography, and nothing in this file
// makes up for that.

func muxConfig(cfg Config) *yamux.Config {
	c := yamux.DefaultConfig()
	// Keepalive is the tunnel layer's job, done the same way on every backend
	// rather than once per multiplexer that happens to offer it.
	c.EnableKeepAlive = false
	c.MaxStreamWindowSize = defaultMuxWindow
	if cfg.StreamWindow > 0 {
		c.MaxStreamWindowSize = uint32(cfg.StreamWindow)
	}
	c.LogOutput = io.Discard
	return c
}

func dialYamux(conn net.Conn, cfg Config) (Session, error) {
	s, err := yamux.Client(conn, muxConfig(cfg))
	if err != nil {
		return nil, fmt.Errorf("yamux: %w", err)
	}
	return muxSession{s}, nil
}

func serveYamux(conn net.Conn, cfg Config) (Session, error) {
	s, err := yamux.Server(conn, muxConfig(cfg))
	if err != nil {
		return nil, fmt.Errorf("yamux: %w", err)
	}
	return muxSession{s}, nil
}

// muxSession is yamux with the one method it is missing, and streams that can
// say "I am done writing" without also saying "I am done".
type muxSession struct{ *yamux.Session }

func (m muxSession) Wait() error {
	<-m.CloseChan()
	return io.EOF
}

func (m muxSession) Open() (net.Conn, error) {
	stream, err := m.Session.OpenStream()
	if err != nil {
		return nil, err
	}
	return muxStream{stream}, nil
}

func (m muxSession) Accept() (net.Conn, error) {
	stream, err := m.Session.AcceptStream()
	if err != nil {
		return nil, err
	}
	return muxStream{stream}, nil
}

// muxStream gives a yamux stream the CloseWrite every other stream in this
// package has.
//
// A forwarded connection is half-closable at both ends — a TCP socket on one
// side, an SSH channel or this on the other — and the tunnel is the only thing
// in the middle. Whoever cannot pass a FIN along as a FIN turns "I have
// finished asking" into "I have finished", which kills the answer while it is
// still being written. Every request/response protocol that frames its request
// by end-of-stream depends on this.
type muxStream struct{ *yamux.Stream }

// CloseWrite sends FIN and nothing else. yamux spells that Close: the stream
// moves to streamLocalClose, which prohibits further local writes and — this is
// the part that matters — goes on delivering everything the peer sends
// (hashicorp/yamux stream.go, Read's streamLocalClose case). Reaching for
// Stream.Shutdown or a full teardown here would drop the reply.
func (s muxStream) CloseWrite() error { return s.Stream.Close() }
