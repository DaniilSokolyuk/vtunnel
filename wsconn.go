package vtunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// wsBufferSize is the read and write buffer gorilla uses per connection.
//
// The default is 4 KiB, which is smaller than a single SSH packet: every packet
// would then be flushed to the socket in several pieces. Sizing the buffers to
// match the 32 KiB copy buffer keeps one packet to one write. There is exactly
// one WebSocket connection per tunnel, so this costs 64 KiB.
const wsBufferSize = 32 * 1024

// NewUpgrader returns a websocket.Upgrader configured for tunnel traffic.
// Origin checks are left open on purpose: the tunnel authenticates with SSH
// keys, and browser-origin rules mean nothing to it.
func NewUpgrader() websocket.Upgrader {
	return websocket.Upgrader{
		HandshakeTimeout: defaultHandshakeTimeout,
		ReadBufferSize:   wsBufferSize,
		WriteBufferSize:  wsBufferSize,
		CheckOrigin:      func(*http.Request) bool { return true },
	}
}

// wsConn wraps a *websocket.Conn as a net.Conn for use with SSH.
// Reads stream directly from the WS message reader to avoid allocations.
// Writes send each call as a single binary WS message.
type wsConn struct {
	*websocket.Conn
	reader io.Reader

	// gorilla allows one concurrent reader and one concurrent writer, and
	// counts the deadline setters as read and write methods. SSH happens to
	// serialize its writes already, but that is its business, not a guarantee
	// to build on.
	writeMu sync.Mutex
}

// NewWSConn wraps a *websocket.Conn as a net.Conn suitable for SSH.
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
// If a ping doesn't get a response within 3x the interval, the connection
// is considered dead and closed — this handles half-open connections where
// the remote end has silently disappeared (no TCP RST/FIN).
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
//
// It deliberately carries no targets, no credentials and no headers: everything
// the controlplane knows about where a domain really goes, and what to inject
// into it, stays on the controlplane. The sandbox learns domain names only.
type listenRequest struct {
	Port int `json:"port"`
	// Domains are routed through this port by the sandbox router.
	Domains []string `json:"domains,omitempty"`
}

// tunnelRequest is the extra data sent when opening a tunnel SSH channel.
type tunnelRequest struct {
	Port int `json:"port"`
}

func marshalJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
