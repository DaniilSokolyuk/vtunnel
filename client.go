package vtunnel

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const defaultPingInterval = 30 * time.Second

// Client connects to a vtunnel server and forwards connections
type Client struct {
	wsURL        string
	headers      http.Header
	conn         *websocket.Conn
	forwards     map[int]string // remotePort -> localAddr
	streams      map[uint32]net.Conn
	mu           sync.RWMutex
	writeMu      sync.Mutex
	done         chan struct{}
	closeOnce    sync.Once
	ctx          context.Context
	cancel       context.CancelFunc
	pingInterval time.Duration
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

// NewClient creates a new vtunnel client
func NewClient(wsURL string, opts ...Option) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		wsURL:        wsURL,
		forwards:     make(map[int]string),
		streams:      make(map[uint32]net.Conn),
		done:         make(chan struct{}),
		ctx:          ctx,
		cancel:       cancel,
		pingInterval: defaultPingInterval,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Connect establishes a WebSocket connection to the server
func (c *Client) Connect() error {
	dialer := websocket.Dialer{}
	conn, _, err := dialer.DialContext(c.ctx, c.wsURL, c.headers)
	if err != nil {
		return err
	}

	c.conn = conn

	// Set up keepalive
	if c.pingInterval > 0 {
		c.conn.SetReadDeadline(time.Now().Add(c.pingInterval * 2))
		c.conn.SetPongHandler(func(string) error {
			c.conn.SetReadDeadline(time.Now().Add(c.pingInterval * 2))
			return nil
		})
		go c.pingLoop()
	}

	go c.readLoop()

	log.Printf("[vtunnel-client] Connected to %s", c.wsURL)
	return nil
}

// Listen requests the server to listen on a remote port and forward to local
func (c *Client) Listen(remotePort int, localAddr string) error {
	c.mu.Lock()
	c.forwards[remotePort] = localAddr
	c.mu.Unlock()

	log.Printf("[vtunnel-client] Requesting listen: remote=%d -> local=%s", remotePort, localAddr)
	return c.sendMessage(Message{Type: MsgListen, Port: remotePort})
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

	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// readLoop reads messages from the server
func (c *Client) readLoop() {
	defer c.conn.Close()

	for {
		select {
		case <-c.done:
			return
		default:
		}

		_, data, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("[vtunnel-client] Read error: %v", err)
			}
			return
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

	conn, err := net.Dial("tcp", localAddr)
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

		c.sendMessage(Message{
			Type:     MsgData,
			StreamID: streamID,
			Data:     buf[:n],
		})
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
func (c *Client) pingLoop() {
	ticker := time.NewTicker(c.pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			c.writeMu.Lock()
			err := c.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(c.pingInterval))
			c.writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

// sendMessage sends a message to the server
func (c *Client) sendMessage(msg Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	return c.conn.WriteMessage(websocket.TextMessage, data)
}
