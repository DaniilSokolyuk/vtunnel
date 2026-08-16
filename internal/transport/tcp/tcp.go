// Package tcp carries a tunnel over plain TCP.
//
// Nothing here encrypts or authenticates anything, and that is not an
// oversight: the session layer above does both, so a tunnel over this is
// exactly as safe as one over TLS. What it buys is the absence of a second
// encryption layer and of WebSocket framing, which is worth measuring when the
// sandbox is somewhere you can reach directly.
package tcp

import (
	"context"
	"net"
	"time"
)

// keepAlivePeriod is long enough not to chatter and short enough that a dead
// peer is noticed before a NAT forgets the connection.
const keepAlivePeriod = 60 * time.Second

// Dial connects to addr.
func Dial(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	SetOptions(conn)
	return conn, nil
}

// Listen accepts tunnel connections on addr. Every accepted connection has the
// same options applied as a dialled one, so which end opened it makes no
// difference to how it behaves.
func Listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &listener{ln}, nil
}

type listener struct{ net.Listener }

func (l *listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	SetOptions(conn)
	return conn, nil
}

// SetOptions enables keepalive and disables Nagle. It is exported because the
// tunnel applies it to the connections it forwards too, which are TCP for
// reasons that have nothing to do with the transport.
func SetOptions(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(keepAlivePeriod)
		tc.SetNoDelay(true)
	}
}
