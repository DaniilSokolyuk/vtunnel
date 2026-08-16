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

// muxSession is yamux with the one method it is missing. Open, Accept and
// Close are already the shapes this package asks for.
type muxSession struct{ *yamux.Session }

func (m muxSession) Wait() error {
	<-m.CloseChan()
	return io.EOF
}
