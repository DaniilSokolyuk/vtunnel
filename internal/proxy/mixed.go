// Package proxy holds the front ends a proxy can be reached through, and the
// plumbing they share. A front end learns one thing — where the client wants to
// go — and hands the connection on; what to do with it belongs to whoever holds
// the allowlist.
package proxy

import (
	"bufio"
	"errors"
	"net"
	"sync"
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
	closing chan struct{}

	// dead is closed when the accept loop has given up, and failed says why.
	// Both are read by Accept, which must keep reporting the failure rather
	// than block once it has happened.
	dead   chan struct{}
	mu     sync.Mutex
	failed error
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
		closing: make(chan struct{}),
		dead:    make(chan struct{}),
	}
	go m.acceptLoop()
	return m
}

// acceptLoop accepts and sorts. Each connection is sniffed on its own
// goroutine, so one client that connects and then thinks about it does not hold
// up the queue behind it.
func (m *MixedListener) acceptLoop() {
	// A temporary failure is not the end of a listener. Descriptor exhaustion
	// and a client that hangs up between the SYN and the accept both surface
	// here, and both pass; returning on them left every later Accept blocked on
	// channels nothing would ever write to again, so one burst — which any
	// client can cause — deafened the proxy for the life of the process.
	// http.Server.Serve backs off and retries for this exact reason, and
	// wrapping its listener is what took that away.
	var backoff time.Duration
	for {
		conn, err := m.ln.Accept()
		if err != nil {
			if !isTemporary(err) {
				m.fail(err)
				return
			}
			backoff = nextBackoff(backoff)
			select {
			case <-time.After(backoff):
				continue
			case <-m.closing:
				return
			}
		}
		backoff = 0
		go m.sort(conn)
	}
}

// fail records the error that ended the loop. Accept keeps answering with it
// rather than blocking: a listener that has stopped has to say so every time it
// is asked, not once.
func (m *MixedListener) fail(err error) {
	m.mu.Lock()
	if m.failed == nil {
		m.failed = err
	}
	m.mu.Unlock()
	close(m.dead)
}

func isTemporary(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	//nolint:staticcheck // Temporary is deprecated, but it is still what a
	// listener reports for the recoverable cases, and net/http reads it too.
	var te interface{ Temporary() bool }
	return errors.As(err, &te) && te.Temporary()
}

func nextBackoff(current time.Duration) time.Duration {
	switch {
	case current == 0:
		return 5 * time.Millisecond
	case current >= time.Second:
		return time.Second
	default:
		return current * 2
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
	case <-m.dead:
		m.mu.Lock()
		defer m.mu.Unlock()
		return nil, m.failed
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
