package vtunnel

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/vivid-money/vtunnel/internal/session"
)

// Protocol selects how the tunnel multiplexes streams over the transport, and
// how the two ends authenticate each other. Both ends must be configured the
// same way: there is no negotiation, deliberately — a preamble exchanged
// before authentication is attack surface, and whoever deploys one end deploys
// the other.
type Protocol string

const (
	// ProtocolSSH is the default, and what vtunnel has always spoken.
	ProtocolSSH Protocol = "ssh"

	// ProtocolYamux multiplexes with yamux over TLS 1.3, both ends' keys
	// pinned to the tunnel secret. Its per-stream window is a setting rather
	// than a constant, which is what SSH cannot offer: golang.org/x/crypto/ssh
	// fixes its channel window at 2 MB, capping one stream at window/RTT on
	// any link with latency.
	ProtocolYamux Protocol = "yamux"

	// ProtocolYamuxInsecure is ProtocolYamux with nothing underneath it: no
	// encryption, no authentication, and the tunnel secret ignored even when
	// one is configured. Whoever can reach the port owns the tunnel, and that
	// means every target of [Client.Listen] and the credential-injecting proxy
	// behind it.
	//
	// It exists so the cost of the cryptography can be measured against the
	// same code path without it. Both ends log a warning naming it, every time
	// they start.
	ProtocolYamuxInsecure Protocol = "yamux-insecure"
)

// insecure reports whether p leaves the tunnel open to anyone who can reach it.
func (p Protocol) insecure() bool { return p == ProtocolYamuxInsecure }

// The tunnel protocol: what vtunnel says once a session exists.
//
// Every stream opens with one length-prefixed JSON header saying what it is
// for. A tunnel stream then carries bytes and nothing else; a control stream
// reads one reply header back and closes.
//
// This lives above the session on purpose. SSH offers channel types, opening
// metadata and global request/reply, and an earlier draft of this leaned on
// all three — which would have meant reimplementing them inside every
// multiplexer that has none, and yamux has none. Written here instead, it is
// written once, and a backend only has to carry bytes on a stream.
//
// A control message is a whole stream rather than a message on a shared one.
// That sounds wasteful and is not: streams are cheap on every backend, and it
// buys concurrent requests with no correlation identifiers and no write lock.

const (
	streamTunnel = "tunnel" // bytes for a forwarded port
	streamListen = "listen" // ask the sandbox to open a port
	streamPing   = "ping"   // keepalive

	// maxFrame bounds a header. Nothing legitimate approaches it; it is here so
	// a corrupt or hostile length cannot make us allocate.
	maxFrame = 64 * 1024

	// headerTimeout bounds how long a stream may stay silent after opening.
	// Without it, a peer that opens streams and never speaks costs a goroutine
	// each.
	headerTimeout = 30 * time.Second
)

// streamHeader is the first thing on every stream.
//
// It deliberately carries no targets, no credentials and no headers:
// everything the controlplane knows about where a domain really goes, and what
// to inject into it, stays on the controlplane. The sandbox learns domain
// names only.
type streamHeader struct {
	Type string `json:"type"`
	Port int    `json:"port,omitempty"`
	// Domains are routed through this port by the sandbox router.
	Domains []string `json:"domains,omitempty"`
}

// streamReply answers a control stream.
type streamReply struct {
	OK    bool   `json:"ok"`
	Port  int    `json:"port,omitempty"`
	Error string `json:"error,omitempty"`
}

func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > maxFrame {
		return fmt.Errorf("frame too large (%d bytes)", len(b))
	}
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf, uint32(len(b)))
	copy(buf[4:], b)
	_, err = w.Write(buf)
	return err
}

func readFrame(r io.Reader, v any) error {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n > maxFrame {
		return fmt.Errorf("frame too large (%d bytes)", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// request opens a control stream, sends h, and waits for the answer.
func request(sess session.Session, h streamHeader) (streamReply, error) {
	stream, err := sess.Open()
	if err != nil {
		return streamReply{}, err
	}
	defer stream.Close()

	stopper := stopAfter(stream, headerTimeout)
	defer stopper()

	if err := writeFrame(stream, h); err != nil {
		return streamReply{}, err
	}
	var reply streamReply
	if err := readFrame(stream, &reply); err != nil {
		return streamReply{}, err
	}
	return reply, nil
}

// openTunnel starts a stream carrying one forwarded connection.
//
// It does not wait for the peer to acknowledge. A refusal arrives as the
// stream closing, which the copy either side of it already handles, and one
// round trip per tunnelled connection is worth more than an earlier log line.
func openTunnel(sess session.Session, port int) (net.Conn, error) {
	stream, err := sess.Open()
	if err != nil {
		return nil, err
	}
	if err := writeFrame(stream, streamHeader{Type: streamTunnel, Port: port}); err != nil {
		stream.Close()
		return nil, err
	}
	return stream, nil
}

// serveStreams reads the header off every stream the peer opens and hands it
// to handle. Ping is answered here, because both ends answer it identically.
//
// handle owns the stream from then on, including closing it.
func serveStreams(sess session.Session, handle func(net.Conn, streamHeader)) {
	for {
		stream, err := sess.Accept()
		if err != nil {
			return
		}
		go func() {
			stopper := stopAfter(stream, headerTimeout)
			var h streamHeader
			err := readFrame(stream, &h)
			stopper()
			if err != nil {
				stream.Close()
				return
			}
			if h.Type == streamPing {
				writeFrame(stream, streamReply{OK: true})
				stream.Close()
				return
			}
			handle(stream, h)
		}()
	}
}

// stopAfter closes c unless the returned function is called first.
//
// A deadline would be the obvious way, and an SSH channel is the one stream
// that cannot have one — so this is how every backend gets the same bound.
func stopAfter(c io.Closer, d time.Duration) func() {
	t := time.AfterFunc(d, func() { c.Close() })
	return func() { t.Stop() }
}

// keepAliveLoop pings until the session dies.
//
// A ping that goes unanswered for three intervals means the peer is gone
// without having said so — a half-open connection, no RST, no FIN — and the
// session is closed so the client can start reconnecting.
func keepAliveLoop(sess session.Session, interval time.Duration) {
	timeout := interval * 3
	for {
		time.Sleep(interval)

		errCh := make(chan error, 1)
		go func() {
			_, err := request(sess, streamHeader{Type: streamPing})
			errCh <- err
		}()

		select {
		case err := <-errCh:
			if err != nil {
				sess.Close()
				return
			}
		case <-time.After(timeout):
			log.Printf("[vtunnel] ping timeout (%v), closing session", timeout)
			sess.Close()
			return
		}
	}
}
