package vtunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/gorilla/websocket"
)

const (
	defaultPingInterval     = 30 * time.Second
	defaultHandshakeTimeout = 60 * time.Second
	defaultCloseWriteWait   = 5 * time.Second
	defaultReconnectMin     = 1 * time.Second
	defaultReconnectMax     = 5 * time.Second
)

var ErrNotConnected = errors.New("vtunnel: not connected")

// Client connects to a vtunnel server and forwards connections
type Client struct {
	wsURL         string
	headers       http.Header
	conn          *websocket.Conn
	connMu        sync.RWMutex
	forwards      map[int]string // remotePort -> localAddr
	streams       map[uint32]net.Conn
	mu            sync.RWMutex
	writeMu       sync.Mutex
	done          chan struct{}
	closeOnce     sync.Once
	ctx           context.Context
	cancel        context.CancelFunc
	pingInterval  time.Duration
	readDeadline  time.Duration
	autoReconnect bool
	reconnectMin  time.Duration
	reconnectMax  time.Duration
}

// Option configures a Client
type Option func(*Client)

// WithPingInterval sets the ping interval (0 = default 30s, negative = disabled)
func WithPingInterval(d time.Duration) Option {
	return func(c *Client) {
		c.pingInterval = d
	}
}

// WithHeaders sets HTTP headers for the WebSocket handshake
func WithHeaders(h http.Header) Option {
	return func(c *Client) {
		c.headers = h
	}
}

// WithAutoReconnect enables or disables automatic reconnects after disconnects.
func WithAutoReconnect(enabled bool) Option {
	return func(c *Client) {
		c.autoReconnect = enabled
	}
}

// WithReconnectBackoff configures the reconnect backoff window.
func WithReconnectBackoff(min, max time.Duration) Option {
	return func(c *Client) {
		c.reconnectMin = min
		c.reconnectMax = max
	}
}

// NewClient creates a new vtunnel client
func NewClient(wsURL string, opts ...Option) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		wsURL:         wsURL,
		forwards:      make(map[int]string),
		streams:       make(map[uint32]net.Conn),
		done:          make(chan struct{}),
		ctx:           ctx,
		cancel:        cancel,
		pingInterval:  defaultPingInterval,
		autoReconnect: false,
		reconnectMin:  defaultReconnectMin,
		reconnectMax:  defaultReconnectMax,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Connect establishes a WebSocket connection to the server
func (c *Client) Connect() error {
	conn, err := c.dialOnce()
	if err != nil {
		return err
	}

	c.setConn(conn)
	errc := c.startConn(conn)
	c.replayForwards()
	if c.autoReconnect {
		go c.reconnectLoop(errc)
	} else {
		go c.waitAndClose(errc)
	}

	log.Printf("[vtunnel-client] Connected to %s", c.wsURL)
	return nil
}

// Listen requests the server to listen on a remote port and forward to local
func (c *Client) Listen(remotePort int, localAddr string) error {
	c.mu.Lock()
	c.forwards[remotePort] = localAddr
	c.mu.Unlock()

	log.Printf("[vtunnel-client] Requesting listen: remote=%d -> local=%s", remotePort, localAddr)
	if err := c.sendMessage(Message{Type: MsgListen, Port: remotePort}); err != nil {
		if c.autoReconnect && errors.Is(err, ErrNotConnected) {
			return nil
		}
		return err
	}
	return nil
}

// Close closes the client and all connections
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		close(c.done)
	})

	c.mu.Lock()
	for _, conn := range c.streams {
		conn.Close()
	}
	c.streams = make(map[uint32]net.Conn)
	c.mu.Unlock()

	return c.closeConn(websocket.CloseNormalClosure, "")
}

// readLoop reads messages from the server
func (c *Client) readLoop(conn *websocket.Conn, errc chan<- error, connDone chan struct{}) {
	defer close(connDone)
	for {
		select {
		case <-c.done:
			return
		default:
		}

		_, data, err := conn.ReadMessage()
		if err != nil {
			if closeErr, ok := err.(*websocket.CloseError); ok {
				log.Printf("[vtunnel-client] Close error: code=%d text=%q", closeErr.Code, closeErr.Text)
			} else if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("[vtunnel-client] Read error: %v", err)
			}
			select {
			case errc <- err:
			default:
			}
			return
		}
		if c.readDeadline > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(c.readDeadline))
		}

		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			log.Printf("[vtunnel-client] Invalid message: %v", err)
			continue
		}

		switch msg.Type {
		case MsgConnect:
			c.handleConnect(msg.StreamID, msg.Port)
		case MsgData:
			c.handleData(msg.StreamID, msg.Data)
		case MsgClose:
			c.handleClose(msg.StreamID)
		case MsgListenOK:
			log.Printf("[vtunnel-client] Listen OK: port=%d", msg.Port)
		case MsgListenErr:
			if msg.Error != "" {
				log.Printf("[vtunnel-client] Listen failed: port=%d error=%s", msg.Port, msg.Error)
			} else {
				log.Printf("[vtunnel-client] Listen failed: port=%d", msg.Port)
			}
		}
	}
}

// handleConnect handles a new connection from the server
func (c *Client) handleConnect(streamID uint32, port int) {
	c.mu.RLock()
	localAddr, ok := c.forwards[port]
	c.mu.RUnlock()

	if !ok {
		log.Printf("[vtunnel-client] No forward for port %d", port)
		c.sendMessage(Message{Type: MsgClose, StreamID: streamID})
		return
	}

	conn, err := c.dialTarget(localAddr)
	if err != nil {
		log.Printf("[vtunnel-client] Failed to connect to %s: %v", localAddr, err)
		c.sendMessage(Message{Type: MsgClose, StreamID: streamID})
		return
	}

	c.mu.Lock()
	c.streams[streamID] = conn
	c.mu.Unlock()

	log.Printf("[vtunnel-client] New stream: id=%d, local=%s", streamID, localAddr)

	// Start reading from local and forwarding to server
	go c.forwardToServer(streamID, conn)
}

// forwardToServer reads from local connection and sends to server
func (c *Client) forwardToServer(streamID uint32, conn net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("[vtunnel-client] Read error on stream %d: %v", streamID, err)
			}
			c.sendMessage(Message{Type: MsgClose, StreamID: streamID})
			c.removeStream(streamID)
			return
		}

		if err := c.sendMessage(Message{
			Type:     MsgData,
			StreamID: streamID,
			Data:     buf[:n],
		}); err != nil {
			log.Printf("[vtunnel-client] Send error on stream %d: %v", streamID, err)
			c.removeStream(streamID)
			return
		}
	}
}

// handleData forwards data from server to local connection
func (c *Client) handleData(streamID uint32, data []byte) {
	c.mu.RLock()
	conn, ok := c.streams[streamID]
	c.mu.RUnlock()

	if !ok {
		return
	}

	if _, err := conn.Write(data); err != nil {
		log.Printf("[vtunnel-client] Write error on stream %d: %v", streamID, err)
		c.removeStream(streamID)
	}
}

// handleClose closes a stream
func (c *Client) handleClose(streamID uint32) {
	c.removeStream(streamID)
}

// removeStream removes and closes a stream
func (c *Client) removeStream(streamID uint32) {
	c.mu.Lock()
	conn, ok := c.streams[streamID]
	if ok {
		delete(c.streams, streamID)
	}
	c.mu.Unlock()

	if ok && conn != nil {
		conn.Close()
	}
}

// pingLoop sends periodic ping messages to keep the connection alive
func (c *Client) pingLoop(conn *websocket.Conn, connDone <-chan struct{}) {
	ticker := time.NewTicker(c.pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-connDone:
			return
		case <-ticker.C:
			c.writeMu.Lock()
			err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(c.pingInterval))
			c.writeMu.Unlock()
			if err != nil {
				log.Printf("[vtunnel-client] Ping failed: %v", err)
				return
			}
		}
	}
}

func (c *Client) closeConn(code int, reason string) error {
	conn := c.getConn()
	if conn == nil {
		return nil
	}
	deadline := time.Now().Add(defaultCloseWriteWait)
	c.writeMu.Lock()
	_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), deadline)
	c.writeMu.Unlock()
	err := conn.Close()
	c.setConn(nil)
	return err
}

// dialTarget dials the target address; if it has a "tls://" prefix,
// a TLS connection is established with the appropriate ServerName,
// and the HTTP Host header is rewritten to match the target host.
func (c *Client) dialTarget(addr string) (net.Conn, error) {
	if after, ok := strings.CutPrefix(addr, "tls://"); ok {
		host, _, err := net.SplitHostPort(after)
		if err != nil {
			return nil, err
		}
		conn, err := tls.Dial("tcp", after, &tls.Config{ServerName: host})
		if err != nil {
			return nil, err
		}
		return newHostRewriteConn(conn, host), nil
	}
	return net.Dial("tcp", addr)
}

// hostRewriteConn wraps a net.Conn and rewrites the HTTP Host header
// to match the target hostname for TLS-terminated connections.
// It scans each Write call for a Host header line and replaces the value.
type hostRewriteConn struct {
	net.Conn
	host    string
	hostBin []byte // pre-built replacement: "Host: <target>\r\n"
}

func newHostRewriteConn(conn net.Conn, host string) *hostRewriteConn {
	return &hostRewriteConn{
		Conn:    conn,
		host:    host,
		hostBin: []byte("Host: " + host + "\r\n"),
	}
}

func (c *hostRewriteConn) Write(p []byte) (int, error) {
	// Fast path: no Host header in this chunk
	const prefix = "\r\nHost: "
	start := bytes.Index(p, []byte(prefix))
	if start == -1 {
		return c.Conn.Write(p)
	}

	// Find end of the Host line
	valueStart := start + len(prefix)
	end := bytes.Index(p[valueStart:], []byte("\r\n"))
	if end == -1 {
		return c.Conn.Write(p)
	}

	// Build rewritten data: before Host line + new Host + after Host line
	var rewritten []byte
	rewritten = append(rewritten, p[:start+2]...) // up to and including \r\n before "Host: "
	rewritten = append(rewritten, c.hostBin...)   // "Host: <target>\r\n"
	rewritten = append(rewritten, p[valueStart+end+2:]...)
	_, err := c.Conn.Write(rewritten)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// sendMessage sends a message to the server
func (c *Client) sendMessage(msg Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	conn := c.getConn()
	if conn == nil {
		return ErrNotConnected
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	return conn.WriteMessage(websocket.TextMessage, data)
}

func (c *Client) setConn(conn *websocket.Conn) {
	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()
}

func (c *Client) getConn() *websocket.Conn {
	c.connMu.RLock()
	conn := c.conn
	c.connMu.RUnlock()
	return conn
}

func (c *Client) startConn(conn *websocket.Conn) chan error {
	connDone := make(chan struct{})
	if c.pingInterval > 0 {
		c.readDeadline = c.pingInterval * 2
		_ = conn.SetReadDeadline(time.Now().Add(c.readDeadline))
		conn.SetPongHandler(func(string) error {
			return conn.SetReadDeadline(time.Now().Add(c.readDeadline))
		})
		go c.pingLoop(conn, connDone)
	} else {
		c.readDeadline = 0
	}

	errc := make(chan error, 1)
	go c.readLoop(conn, errc, connDone)
	return errc
}

func (c *Client) waitAndClose(errc <-chan error) {
	select {
	case <-c.done:
		return
	case <-errc:
		c.Close()
	}
}

func (c *Client) reconnectLoop(errc chan error) {
	bo := c.newBackoff()
	for {
		select {
		case <-c.done:
			return
		case <-errc:
		}

		c.disconnectCleanup()
		bo.Reset()
		for {
			if c.ctx.Err() != nil {
				return
			}
			conn, err := c.dialOnce()
			if err != nil {
				delay := bo.NextBackOff()
				select {
				case <-c.done:
					return
				case <-time.After(delay):
				}
				continue
			}
			if c.ctx.Err() != nil {
				_ = conn.Close()
				return
			}
			c.setConn(conn)
			errc = c.startConn(conn)
			c.replayForwards()
			log.Printf("[vtunnel-client] Reconnected to %s", c.wsURL)
			break
		}
	}
}

func (c *Client) dialOnce() (*websocket.Conn, error) {
	dialer := websocket.Dialer{
		HandshakeTimeout: defaultHandshakeTimeout,
	}
	conn, _, err := dialer.DialContext(c.ctx, c.wsURL, c.headers)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *Client) disconnectCleanup() {
	conn := c.getConn()
	if conn != nil {
		_ = conn.Close()
		c.setConn(nil)
	}
	c.mu.Lock()
	for _, stream := range c.streams {
		stream.Close()
	}
	c.streams = make(map[uint32]net.Conn)
	c.mu.Unlock()
}

func (c *Client) replayForwards() {
	c.mu.RLock()
	ports := make([]int, 0, len(c.forwards))
	for port := range c.forwards {
		ports = append(ports, port)
	}
	c.mu.RUnlock()

	for _, port := range ports {
		if err := c.sendMessage(Message{Type: MsgListen, Port: port}); err != nil && !errors.Is(err, ErrNotConnected) {
			log.Printf("[vtunnel-client] Re-listen failed for port %d: %v", port, err)
		}
	}
}

func (c *Client) newBackoff() *backoff.ExponentialBackOff {
	min := c.reconnectMin
	if min <= 0 {
		min = defaultReconnectMin
	}
	max := c.reconnectMax
	if max <= 0 {
		max = defaultReconnectMax
	}
	if max < min {
		max = min
	}

	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = min
	bo.MaxInterval = max
	bo.Multiplier = 2
	bo.RandomizationFactor = 0
	bo.MaxElapsedTime = 0
	return bo
}
