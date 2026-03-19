package vtunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
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

// keepAliveLoop sends SSH ping requests until the connection dies.
// Deprecated: will be removed when server.go/client.go are migrated to yamux.
func keepAliveLoop(sshConn ssh.Conn, interval time.Duration) {
	timeout := interval * 3
	for {
		time.Sleep(interval)
		errCh := make(chan error, 1)
		go func() {
			_, _, err := sshConn.SendRequest("ping", true, nil)
			errCh <- err
		}()
		select {
		case err := <-errCh:
			if err != nil {
				sshConn.Close()
				return
			}
		case <-time.After(timeout):
			log.Printf("[vtunnel] ping timeout (%v), closing connection", timeout)
			sshConn.Close()
			return
		}
	}
}

// handleRequests replies to SSH ping requests (keepalive).
// Deprecated: will be removed when server.go/client.go are migrated to yamux.
func handleRequests(reqs <-chan *ssh.Request) {
	for r := range reqs {
		switch r.Type {
		case "ping":
			r.Reply(true, []byte("pong"))
		default:
			if r.WantReply {
				r.Reply(false, nil)
			}
		}
	}
}

// rejectChannels rejects all incoming SSH channels.
// Deprecated: will be removed when server.go/client.go are migrated to yamux.
func rejectChannels(chans <-chan ssh.NewChannel) {
	for ch := range chans {
		ch.Reject(ssh.Prohibited, "not supported")
	}
}

// generateHostKey creates an ephemeral ECDSA P-256 key for SSH.
// Deprecated: will be removed when server.go/client.go are migrated to yamux.
func generateHostKey() (ssh.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
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
