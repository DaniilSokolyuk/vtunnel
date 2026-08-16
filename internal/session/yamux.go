package session

import (
	"fmt"
	"io"
	"net"

	"github.com/hashicorp/yamux"
)

// The per-stream window is left at yamux's own default of 256 KB, which is
// also what gost settles for — it overrides nothing either.
//
// It is a deliberate choice against the throughput this backend exists to
// offer, and the reason is memory. yamux does not grow the window towards a
// ceiling: sendWindowUpdate hands out the whole of MaxStreamWindowSize as soon
// as the application reads, so the figure is a flat per-stream buffer, paid
// for every tunnelled connection at once. A sandbox with fifty of them open
// costs fifty times whatever this is, on both ends, and a container is a place
// where that is noticed.
//
// So the default is the cheap one and the fast one is asked for:
// Config.StreamWindow, reachable as WithStreamWindow and
// WithServerStreamWindow. Anyone moving large objects over a link with real
// latency wants it, and the arithmetic for how much is in those docs.

// conn arrives already authenticated and encrypted — see secureClient and
// secureServer. yamux itself brings no cryptography, and nothing in this file
// makes up for that.

func muxConfig(cfg Config) *yamux.Config {
	c := yamux.DefaultConfig()
	// Keepalive is the tunnel layer's job, done the same way on every backend
	// rather than once per multiplexer that happens to offer it.
	c.EnableKeepAlive = false
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
