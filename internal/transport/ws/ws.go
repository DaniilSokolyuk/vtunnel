// Package ws carries a tunnel over a WebSocket.
//
// It is a transport and nothing more: it turns a WebSocket into an ordered
// stream of bytes and hands it over. Everything that makes the tunnel safe
// happens above it, in package session, which is why running over ws:// and
// running over wss:// come to the same thing.
//
// The accepting half is a net.Listener like any other, even though a
// WebSocket server is an HTTP server underneath. [Listen] runs that server and
// hands upgraded connections out of Accept, so the tunnel above never learns
// the difference. A deployment that needs the tunnel mounted on its own mux —
// next to a health endpoint, say — uses [Upgrader] and [Conn] directly instead.
package ws

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// BufferSize is the read and write buffer gorilla uses per connection.
//
// The default is 4 KiB, which is smaller than a single session packet: every
// packet would then be flushed to the socket in several pieces. Sizing the
// buffers to match the 32 KiB copy buffer keeps one packet to one write. There
// is exactly one WebSocket connection per tunnel, so this costs 64 KiB.
const BufferSize = 32 * 1024

// Upgrader returns a websocket.Upgrader configured for tunnel traffic.
// Origin checks are left open on purpose: the tunnel authenticates itself in
// the session layer, and browser-origin rules mean nothing to it.
func Upgrader(handshakeTimeout time.Duration) websocket.Upgrader {
	return websocket.Upgrader{
		HandshakeTimeout: handshakeTimeout,
		ReadBufferSize:   BufferSize,
		WriteBufferSize:  BufferSize,
		CheckOrigin:      func(*http.Request) bool { return true },
	}
}

// Dial opens a WebSocket to url and presents it as a net.Conn.
func Dial(ctx context.Context, url string, headers http.Header, handshakeTimeout time.Duration) (net.Conn, error) {
	dialer := websocket.Dialer{
		HandshakeTimeout: handshakeTimeout,
		ReadBufferSize:   BufferSize,
		WriteBufferSize:  BufferSize,
		// The controlplane is someone's laptop, which may only reach the
		// sandbox through a corporate proxy. gorilla's own DefaultDialer does
		// this; a zero Dialer would silently ignore the environment.
		Proxy: http.ProxyFromEnvironment,
	}
	wsConn, _, err := dialer.DialContext(ctx, url, headers)
	if err != nil {
		return nil, err
	}
	return Conn(wsConn), nil
}

// Listen accepts tunnel connections on addr, upgrading requests to path.
// An empty path means "/".
func Listen(addr, path string, handshakeTimeout time.Duration) (net.Listener, error) {
	tcpLn, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if path == "" {
		path = "/"
	}

	l := &listener{
		addr:  tcpLn.Addr(),
		conns: make(chan net.Conn),
		done:  make(chan struct{}),
	}
	up := Upgrader(handshakeTimeout)

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		wsConn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return // Upgrade has already answered
		}
		// Upgrade hijacks the connection, so returning from this handler does
		// not close it. Ownership passes to whoever takes it out of Accept.
		select {
		case l.conns <- Conn(wsConn):
		case <-l.done:
			wsConn.Close()
		}
	})

	l.srv = &http.Server{
		Handler: mux,
		// A peer that opens a connection and dawdles over the request line
		// cannot pin a goroutine indefinitely. No read or write timeout: once
		// upgraded, this connection is a long-lived tunnel.
		ReadHeaderTimeout: 10 * time.Second,
	}
	go l.srv.Serve(tcpLn)
	return l, nil
}

type listener struct {
	addr  net.Addr
	conns chan net.Conn
	srv   *http.Server
	done  chan struct{}
	once  sync.Once
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *listener) Addr() net.Addr { return l.addr }

func (l *listener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.done)
		err = l.srv.Close()
	})
	return err
}

// Conn presents a *websocket.Conn as a net.Conn.
//
// Reads stream directly from the WebSocket message reader to avoid
// allocations. Writes send each call as a single binary message.
func Conn(ws *websocket.Conn) net.Conn {
	return &wsConn{Conn: ws}
}

type wsConn struct {
	*websocket.Conn
	reader io.Reader

	// gorilla allows one concurrent reader and one concurrent writer, and
	// counts the deadline setters as read and write methods. A session
	// serializes its writes already, but that is its business, not a guarantee
	// to build on.
	writeMu sync.Mutex
}

func (c *wsConn) Read(dst []byte) (int, error) {
	for {
		if c.reader != nil {
			n, err := c.reader.Read(dst)
			if err == io.EOF {
				c.reader = nil
			}
			if n > 0 {
				return n, nil
			}
			if err != nil && err != io.EOF {
				return 0, err
			}
			continue
		}
		_, r, err := c.Conn.NextReader()
		if err != nil {
			return 0, err
		}
		c.reader = r
	}
}

func (c *wsConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := c.Conn.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *wsConn) SetWriteDeadline(t time.Time) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.Conn.SetWriteDeadline(t)
}

func (c *wsConn) SetDeadline(t time.Time) error {
	if err := c.Conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}
