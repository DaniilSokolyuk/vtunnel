// Package session multiplexes one net.Conn into many byte streams, and
// authenticates the two ends to each other while doing it.
//
// The interface is deliberately as small as a multiplexer can be: open a
// stream, accept a stream, wait, close. Everything the tunnel needs on top of
// that — which port a stream belongs to, asking the sandbox to listen and
// hearing back which port it got, keepalive — is a header written into a
// stream, not a feature of the session. That framing lives one layer up, in
// package vtunnel, and is written once for every backend rather than once per
// backend.
//
// Authentication belongs here and only here. The transport underneath hands us
// a net.Conn and contributes nothing to security: it may be a WebSocket over
// TLS, or plain TCP, and the tunnel must be exactly as safe either way.
package session

import (
	"fmt"
	"net"
	"time"

	"github.com/vivid-money/vtunnel/internal/tunnelkey"
)

// Session is a live multiplexed connection to the peer.
//
// Open and Accept are safe for concurrent use; one goroutine per tunnelled
// connection is the normal pattern.
type Session interface {
	// Open starts a new stream to the peer.
	Open() (net.Conn, error)

	// Accept returns the next stream the peer opened. It returns an error once
	// the session is finished.
	Accept() (net.Conn, error)

	// Wait blocks until the session ends, and reports why.
	Wait() error

	// Close tears the session down, along with every stream on it.
	Close() error
}

// Kind selects a session implementation. Both ends must be configured with the
// same one: there is no negotiation, deliberately. A preamble exchanged before
// authentication is attack surface that buys us nothing here, since whoever
// deploys one end deploys the other.
type Kind string

const (
	// KindSSH speaks SSH, as vtunnel always has. Encryption and mutual
	// authentication come from golang.org/x/crypto/ssh.
	KindSSH Kind = "ssh"

	// KindYamux speaks yamux over TLS 1.3 with both ends' keys pinned.
	KindYamux Kind = "yamux"

	// KindYamuxInsecure is KindYamux with the TLS taken away: no encryption,
	// no authentication, the tunnel secret ignored entirely. It exists to
	// measure what the cryptography costs, by being the same code path without
	// it.
	KindYamuxInsecure Kind = "yamux-insecure"
)

// Config is everything a backend needs that is not the connection itself.
type Config struct {
	// Keys authenticates both ends. A nil Keys leaves the session
	// unauthenticated and unpinned — the caller is expected to have said so,
	// loudly, somewhere the operator will see it.
	Keys *tunnelkey.Keys

	// Handshake bounds the setup exchange. Zero means no bound.
	Handshake time.Duration

	// StreamWindow is the per-stream receive window, in bytes. Zero takes
	// defaultMuxWindow, which explains why it is not yamux's own default.
	//
	// It is the ceiling on one stream: a sender may have this much in flight
	// unacknowledged, so a single stream tops out at StreamWindow/RTT no matter
	// how fat the link is.
	//
	// Raising it is not free: this much may be buffered for every concurrent
	// stream, which is why the default is the small one.
	//
	// Only the multiplexing backends honour it. KindSSH ignores it —
	// golang.org/x/crypto/ssh fixes its channel window at 2 MB and offers no
	// way to ask for more, which is the concrete reason there is a second
	// backend at all.
	StreamWindow int
}

// Dial runs the client half of the handshake on an established connection.
//
// conn is consumed either way: on error it has been closed.
func Dial(kind Kind, conn net.Conn, cfg Config) (Session, error) {
	return setUp(conn, cfg, func(c net.Conn) (Session, error) {
		switch kind {
		case KindSSH, "":
			return dialSSH(c, cfg)
		case KindYamux:
			sec, err := secureClient(c, cfg)
			if err != nil {
				return nil, err
			}
			return dialYamux(sec, cfg)
		case KindYamuxInsecure:
			return dialYamux(c, cfg)
		default:
			return nil, fmt.Errorf("unknown session kind %q", kind)
		}
	})
}

// Serve runs the server half of the handshake on an accepted connection.
//
// conn is consumed either way: on error it has been closed.
func Serve(kind Kind, conn net.Conn, cfg Config) (Session, error) {
	return setUp(conn, cfg, func(c net.Conn) (Session, error) {
		switch kind {
		case KindSSH, "":
			return serveSSH(c, cfg)
		case KindYamux:
			sec, err := secureServer(c, cfg)
			if err != nil {
				return nil, err
			}
			return serveYamux(sec, cfg)
		case KindYamuxInsecure:
			return serveYamux(c, cfg)
		default:
			return nil, fmt.Errorf("unknown session kind %q", kind)
		}
	})
}

// setUp bounds the handshake and disposes of the connection if it fails, so
// that no backend has to remember to. A handshake with no bound is how a peer
// that stops talking mid-exchange keeps a goroutine and a socket forever.
func setUp(conn net.Conn, cfg Config, handshake func(net.Conn) (Session, error)) (Session, error) {
	if cfg.Handshake > 0 {
		conn.SetDeadline(time.Now().Add(cfg.Handshake))
	}
	sess, err := handshake(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if cfg.Handshake > 0 {
		conn.SetDeadline(time.Time{})
	}
	return sess, nil
}
