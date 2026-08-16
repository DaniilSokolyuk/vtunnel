// Package proxy holds the front ends a proxy can be reached through, and the
// plumbing they share. A front end learns one thing — where the client wants to
// go — and hands the connection on; what to do with it belongs to whoever holds
// the allowlist.
package proxy

import (
	"bufio"
	"net"
	"time"

	"github.com/vivid-money/vtunnel/internal/proxy/socks5"
)

// MixedListener serves HTTP and SOCKS5 on one port.
//
// A SOCKS5 client opens with the protocol version byte; an HTTP client opens
// with a method, which is always a letter. One byte tells them apart, so a
// sandbox can point HTTP_PROXY and ALL_PROXY at the same address instead of
// running two listeners with two firewall rules and two ways to get it wrong.
// clash and sing-box call this a mixed port; glider spells it mixed://.
//
// SOCKS5 connections go to the handler passed to [NewMixed]. Everything else
// comes out of Accept, so an [net/http.Server] can serve it unchanged.
type MixedListener struct {
	ln      net.Listener
	socks   func(net.Conn)
	peek    time.Duration
	conns   chan net.Conn
	errs    chan error
	closing chan struct{}
}

// NewMixed starts sorting connections arriving on ln. peek bounds how long a
// client may stay silent before it is hung up on: without it, a peer that
// connects and says nothing costs a goroutine and a descriptor for as long as
// the process lives.
//
// The handler owns the connection it is given, including closing it.
func NewMixed(ln net.Listener, peek time.Duration, socks func(net.Conn)) *MixedListener {
	m := &MixedListener{
		ln:      ln,
		socks:   socks,
		peek:    peek,
		conns:   make(chan net.Conn),
		errs:    make(chan error, 1),
		closing: make(chan struct{}),
	}
	go m.acceptLoop()
	return m
}

// acceptLoop accepts and sorts. Each connection is sniffed on its own
// goroutine, so one client that connects and then thinks about it does not hold
// up the queue behind it.
func (m *MixedListener) acceptLoop() {
	for {
		conn, err := m.ln.Accept()
		if err != nil {
			select {
			case m.errs <- err:
			default:
			}
			return
		}
		go m.sort(conn)
	}
}

func (m *MixedListener) sort(conn net.Conn) {
	if m.peek > 0 {
		conn.SetReadDeadline(time.Now().Add(m.peek))
	}
	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	if err != nil {
		conn.Close()
		return
	}
	if m.peek > 0 {
		// Cleared before the traffic starts: this deadline is about the
		// handshake, and the connection that follows sets its own pace.
		conn.SetReadDeadline(time.Time{})
	}

	// The bytes already read have to travel with the connection, or the
	// protocol loses its first byte to the sniff.
	sorted := &peekedConn{Conn: conn, r: br}

	if first[0] == socks5.Version {
		if m.socks == nil {
			conn.Close()
			return
		}
		m.socks(sorted)
		return
	}

	select {
	case m.conns <- sorted:
	case <-m.closing:
		conn.Close()
	}
}

// Accept returns the next connection that is not SOCKS5.
func (m *MixedListener) Accept() (net.Conn, error) {
	select {
	case conn := <-m.conns:
		return conn, nil
	case err := <-m.errs:
		return nil, err
	case <-m.closing:
		return nil, net.ErrClosed
	}
}

// Close stops accepting. Connections already handed out are the caller's.
func (m *MixedListener) Close() error {
	select {
	case <-m.closing:
		return nil
	default:
		close(m.closing)
	}
	return m.ln.Close()
}

// Addr returns the address being listened on.
func (m *MixedListener) Addr() net.Addr { return m.ln.Addr() }

// peekedConn is a connection whose first bytes have already been read, reading
// them back out before anything else.
type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// CloseWrite forwards a half-close to the wrapped connection when it can do
// one, and says so plainly when it cannot — a caller that reads success here
// would wait for an EOF nobody is going to send.
func (c *peekedConn) CloseWrite() error {
	cw, ok := c.Conn.(interface{ CloseWrite() error })
	if !ok {
		return net.ErrClosed
	}
	return cw.CloseWrite()
}
