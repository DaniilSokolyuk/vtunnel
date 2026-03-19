package vtunnel

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// wsConn wraps a *websocket.Conn as a net.Conn for use with h2mux.
// Reads stream directly from the WS message reader to avoid allocations.
// Writes send each call as a single binary WS message.
type wsConn struct {
	*websocket.Conn
	reader io.Reader
}

// NewWSConn wraps a *websocket.Conn as a net.Conn suitable for h2mux.
func NewWSConn(ws *websocket.Conn) net.Conn {
	return &wsConn{Conn: ws}
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
	if err := c.Conn.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *wsConn) SetDeadline(t time.Time) error {
	if err := c.Conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.Conn.SetWriteDeadline(t)
}

// pipe copies bidirectionally between a and b using io.Copy.
// When either direction finishes (EOF or error), both sides are closed.
// Blocks until both directions complete.
func pipe(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	var once sync.Once
	closeBoth := func() {
		a.Close()
		b.Close()
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(a, b)
		once.Do(closeBoth)
	}()
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		once.Do(closeBoth)
	}()
	wg.Wait()
}

// setTCPOptions enables keepalive and disables Nagle on TCP connections.
func setTCPOptions(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(60 * time.Second)
		tc.SetNoDelay(true)
	}
}

// listenRequest is the JSON body for listen/forward control requests.
type listenRequest struct {
	Port      int    `json:"port"`
	LocalAddr string `json:"local_addr,omitempty"`
	Domain    string `json:"domain,omitempty"` // proxy domain mapping (used by Forward)
}

// listenResponse is the JSON response for listen/forward control requests.
type listenResponse struct {
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	Port      int    `json:"port,omitempty"`
	LocalAddr string `json:"local_addr,omitempty"`
}
