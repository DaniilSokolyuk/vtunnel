package vtunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// wsConn wraps a *websocket.Conn as a net.Conn for use with SSH.
// Reads buffer leftover bytes from oversized WS messages.
// Writes send each call as a single binary WS message.
type wsConn struct {
	*websocket.Conn
	buff []byte
}

func newWSConn(ws *websocket.Conn) net.Conn {
	return &wsConn{Conn: ws}
}

func (c *wsConn) Read(dst []byte) (int, error) {
	var src []byte
	if len(c.buff) > 0 {
		src = c.buff
		c.buff = nil
	} else if _, msg, err := c.Conn.ReadMessage(); err == nil {
		src = msg
	} else {
		return 0, err
	}
	n := copy(dst, src)
	if n < len(src) {
		c.buff = make([]byte, len(src)-n)
		copy(c.buff, src[n:])
	}
	return n, nil
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
func keepAliveLoop(sshConn ssh.Conn, interval time.Duration) {
	for {
		time.Sleep(interval)
		_, _, err := sshConn.SendRequest("ping", true, nil)
		if err != nil {
			sshConn.Close()
			return
		}
	}
}

// handleRequests replies to SSH ping requests (keepalive).
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
func rejectChannels(chans <-chan ssh.NewChannel) {
	for ch := range chans {
		ch.Reject(ssh.Prohibited, "not supported")
	}
}

// generateHostKey creates an ephemeral ECDSA P-256 key for SSH.
func generateHostKey() (ssh.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}

// listenRequest is sent by the client to request the server to listen on a port.
type listenRequest struct {
	Port      int    `json:"port"`
	LocalAddr string `json:"local_addr,omitempty"`
}

// tunnelRequest is the extra data sent when opening a tunnel SSH channel.
type tunnelRequest struct {
	Port int `json:"port"`
}

func marshalJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
