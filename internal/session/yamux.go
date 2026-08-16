package session

import (
	"fmt"
	"io"
	"net"

	"github.com/hashicorp/yamux"
)

// defaultMuxWindow is the per-stream receive window when Config says nothing.
//
// It is set equal to what golang.org/x/crypto/ssh hard-codes, so that swapping
// backends changes the multiplexer and not the flow control underneath it.
// Unlike SSH's, this one is a setting: see Config.StreamWindow.
const defaultMuxWindow = 2 * 1024 * 1024

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
