package vtunnel

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// wsConn wraps a *websocket.Conn as a net.Conn for use with yamux.
// Reads stream directly from the WS message reader to avoid allocations.
// Writes send each call as a single binary WS message.
type wsConn struct {
	*websocket.Conn
	reader io.Reader
}

// NewWSConn wraps a *websocket.Conn as a net.Conn suitable for yamux.
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
	cp := func(dst, src io.ReadWriteCloser) {
		defer wg.Done()
		bufPtr := pipeBufPool.Get().(*[]byte)
		io.CopyBuffer(dst, src, (*bufPtr)[:cap(*bufPtr)])
		pipeBufPool.Put(bufPtr)
		once.Do(closeBoth)
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

var pipeBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 32*1024)
		return &buf
	},
}

// setTCPOptions enables keepalive and disables Nagle on TCP connections.
func setTCPOptions(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(60 * time.Second)
		tc.SetNoDelay(true)
	}
}

// maxMsgSize is the maximum allowed message size for length-prefixed JSON messages (1 MB).
const maxMsgSize = 1 << 20

// writeMsg writes a length-prefixed JSON message: [4-byte big-endian uint32 length][JSON payload].
func writeMsg(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// readMsg reads a length-prefixed JSON message: [4-byte big-endian uint32 length][JSON payload].
func readMsg(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxMsgSize {
		return fmt.Errorf("message too large: %d bytes (max %d)", n, maxMsgSize)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, v)
}

// controlRequest is sent by the client on the control stream.
type controlRequest struct {
	ID   uint32 `json:"id"`
	Type string `json:"type"` // "listen"
	listenRequest
}

// controlResponse is sent by the server on the control stream.
type controlResponse struct {
	ID    uint32 `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	listenRequest
}

// listenRequest is sent by the client to request the server to listen on a port.
type listenRequest struct {
	Port      int    `json:"port"`
	LocalAddr string `json:"local_addr,omitempty"`
	Domain    string `json:"domain,omitempty"` // proxy domain mapping (used by Forward)
}

// tunnelRequest is the header sent when opening a tunnel stream.
type tunnelRequest struct {
	Port int `json:"port"`
}

func marshalJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
