package vtunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

const (
	defaultHandshakeTimeout = 60 * time.Second
	defaultDialTimeout      = 10 * time.Second
	defaultReconnectMin     = 1 * time.Second
	defaultReconnectMax     = 5 * time.Second
)

// Client connects to a vtunnel server and forwards connections.
type Client struct {
	wsURL     string
	headers   http.Header
	session   *yamux.Session
	connMu    sync.RWMutex
	forwards  map[int]string // remotePort -> localAddr
	mu        sync.RWMutex
	done      chan struct{}
	closeOnce sync.Once
	ctx       context.Context
	cancel    context.CancelFunc

	keepAlive    time.Duration
	reconnectMin time.Duration
	reconnectMax time.Duration
	privKey      ed25519.PrivateKey // nil = no auth

	// Control stream state
	ctrlStream *yamux.Stream
	ctrlMu     sync.Mutex // serialize writes to control stream
	pending    map[uint32]chan controlResponse
	pendingMu  sync.Mutex
	nextID     atomic.Uint32

	// Domain-based forwards (Forward method)
	domainForwards map[string]string // domain -> localAddr
}

// Option configures a Client.
type Option func(*Client)

// WithKeepAlive sets the keepalive ping interval (0 = default 30s, negative = disabled).
func WithKeepAlive(d time.Duration) Option {
	return func(c *Client) {
		c.keepAlive = d
	}
}

// WithPingInterval is an alias for WithKeepAlive for backward compatibility.
func WithPingInterval(d time.Duration) Option {
	return WithKeepAlive(d)
}

// WithHeaders sets HTTP headers for the WebSocket handshake.
func WithHeaders(h http.Header) Option {
	return func(c *Client) {
		c.headers = h
	}
}

// WithReconnectBackoff configures the reconnect backoff window.
func WithReconnectBackoff(min, max time.Duration) Option {
	return func(c *Client) {
		c.reconnectMin = min
		c.reconnectMax = max
	}
}

// WithKey sets the client private key for authentication ("vt-priv-...").
// When set, the client authenticates via ed25519 challenge-response handshake
// and verifies the server's identity using a derived hash.
func WithKey(privKey string) Option {
	return func(c *Client) {
		key, err := parsePrivateKey(privKey)
		if err != nil {
			panic(fmt.Sprintf("vtunnel: invalid key: %v", err))
		}
		c.privKey = key
	}
}

// NewClient creates a new vtunnel client.
func NewClient(wsURL string, opts ...Option) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		wsURL:          wsURL,
		forwards:       make(map[int]string),
		domainForwards: make(map[string]string),
		done:           make(chan struct{}),
		ctx:            ctx,
		cancel:         cancel,
		keepAlive:      defaultKeepAlive,
		reconnectMin:   defaultReconnectMin,
		reconnectMax:   defaultReconnectMax,
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.privKey == nil {
		log.Println("[vtunnel-client] WARNING: No key configured. Authentication is DISABLED. Do NOT use in production! Use --key or VTUNNEL_KEY.")
	}
	return c
}

// Connect establishes a WebSocket+yamux connection to the server.
func (c *Client) Connect() error {
	if err := c.connectOnce(); err != nil {
		return err
	}
	log.Printf("[vtunnel-client] Connected to %s", c.wsURL)
	go c.connectionLoop()
	return nil
}

// Listen requests the server to listen on a remote port and forward to local.
func (c *Client) Listen(remotePort int, localAddr string) error {
	c.mu.Lock()
	c.forwards[remotePort] = localAddr
	c.mu.Unlock()

	log.Printf("[vtunnel-client] Requesting listen: remote=%d -> local=%s", remotePort, localAddr)

	session := c.getSession()
	if session == nil {
		return nil // will be replayed on reconnect
	}

	return c.sendListen(remotePort, localAddr)
}

// Forward registers a domain-based forward. The proxy on the server will route
// requests for the given domain through the tunnel. The server auto-allocates
// an internal port; the caller only deals with domain names.
func (c *Client) Forward(domain, localAddr string) error {
	c.mu.Lock()
	c.domainForwards[domain] = localAddr
	c.mu.Unlock()

	log.Printf("[vtunnel-client] Requesting forward: %s -> %s", domain, localAddr)

	session := c.getSession()
	if session == nil {
		return nil // will be replayed on reconnect
	}

	return c.sendListenWithDomain(localAddr, domain)
}

// Close closes the client and all connections.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		close(c.done)
	})

	session := c.getSession()
	if session != nil {
		session.Close()
		c.setSession(nil)
	}
	return nil
}

// dialOnce establishes a single WS+yamux connection.
func (c *Client) dialOnce() (*yamux.Session, error) {
	dialer := websocket.Dialer{
		HandshakeTimeout: defaultHandshakeTimeout,
	}
	wsConn, _, err := dialer.DialContext(c.ctx, c.wsURL, c.headers)
	if err != nil {
		return nil, err
	}

	conn := NewWSConn(wsConn)

	// Custom auth handshake
	conn.SetDeadline(time.Now().Add(defaultHandshakeTimeout))
	if err := clientHandshake(conn, c.privKey); err != nil {
		wsConn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}
	conn.SetDeadline(time.Time{})

	// Create yamux client session
	cfg := c.yamuxConfig()
	session, err := yamux.Client(conn, cfg)
	if err != nil {
		wsConn.Close()
		return nil, fmt.Errorf("yamux session: %w", err)
	}

	// Open control stream (first stream)
	ctrlStream, err := session.OpenStream()
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("open control stream: %w", err)
	}
	c.ctrlStream = ctrlStream
	c.pending = make(map[uint32]chan controlResponse)

	// Start background goroutines
	go c.readControlResponses(ctrlStream)
	go c.acceptTunnelStreams(session)

	return session, nil
}

// yamuxConfig returns the yamux configuration for the client.
func (c *Client) yamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.MaxStreamWindowSize = 16 * 1024 * 1024
	cfg.ConnectionWriteTimeout = 10 * time.Second
	cfg.StreamOpenTimeout = 10 * time.Second
	cfg.LogOutput = io.Discard
	if c.keepAlive > 0 {
		cfg.EnableKeepAlive = true
		cfg.KeepAliveInterval = c.keepAlive
		// Adapt write timeout so keepalive pings time out promptly
		if t := c.keepAlive * 3; t < cfg.ConnectionWriteTimeout {
			cfg.ConnectionWriteTimeout = t
		}
	} else {
		cfg.EnableKeepAlive = false
	}
	return cfg
}

// readControlResponses reads responses from the control stream and dispatches
// them to the appropriate pending request channel by ID.
func (c *Client) readControlResponses(stream *yamux.Stream) {
	for {
		var resp controlResponse
		if err := readMsg(stream, &resp); err != nil {
			// Session dying, clean up all pending
			c.pendingMu.Lock()
			for id, ch := range c.pending {
				close(ch)
				delete(c.pending, id)
			}
			c.pendingMu.Unlock()
			return
		}
		c.pendingMu.Lock()
		if ch, ok := c.pending[resp.ID]; ok {
			ch <- resp
			delete(c.pending, resp.ID)
		}
		c.pendingMu.Unlock()
	}
}

// sendControl sends a control request and waits for the response.
func (c *Client) sendControl(req controlRequest) (controlResponse, error) {
	id := c.nextID.Add(1)
	req.ID = id

	ch := make(chan controlResponse, 1)
	c.pendingMu.Lock()
	c.pending[id] = ch
	c.pendingMu.Unlock()

	c.ctrlMu.Lock()
	err := writeMsg(c.ctrlStream, req)
	c.ctrlMu.Unlock()
	if err != nil {
		c.pendingMu.Lock()
		delete(c.pending, id)
		c.pendingMu.Unlock()
		return controlResponse{}, err
	}

	select {
	case resp, ok := <-ch:
		if !ok {
			return controlResponse{}, fmt.Errorf("connection closed")
		}
		return resp, nil
	case <-c.ctx.Done():
		c.pendingMu.Lock()
		delete(c.pending, id)
		c.pendingMu.Unlock()
		return controlResponse{}, c.ctx.Err()
	}
}

// acceptTunnelStreams accepts incoming yamux streams from the server (tunnel data).
func (c *Client) acceptTunnelStreams(session *yamux.Session) {
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			return // session closed
		}
		go c.handleTunnel(stream)
	}
}

// handleTunnel reads the tunnel header from a stream and pipes to the local target.
func (c *Client) handleTunnel(stream *yamux.Stream) {
	defer stream.Close()

	var req tunnelRequest
	if err := readMsg(stream, &req); err != nil {
		log.Printf("[vtunnel-client] Read tunnel header failed: %v", err)
		return
	}

	c.mu.RLock()
	localAddr, ok := c.forwards[req.Port]
	c.mu.RUnlock()

	if !ok {
		log.Printf("[vtunnel-client] No forward for port %d", req.Port)
		return
	}

	localConn, err := c.dialTarget(localAddr)
	if err != nil {
		log.Printf("[vtunnel-client] Failed to connect to %s: %v", localAddr, err)
		return
	}

	log.Printf("[vtunnel-client] New tunnel: port=%d -> %s", req.Port, localAddr)
	pipe(stream, localConn)
}

// dialTarget dials the target address; if it has a "tls://" prefix,
// a TLS connection is established with the appropriate ServerName.
func (c *Client) dialTarget(addr string) (net.Conn, error) {
	if after, ok := strings.CutPrefix(addr, "tls://"); ok {
		host, _, err := net.SplitHostPort(after)
		if err != nil {
			return nil, err
		}
		dialer := &net.Dialer{Timeout: defaultDialTimeout}
		conn, err := tls.DialWithDialer(dialer, "tcp", after, &tls.Config{ServerName: host})
		if err != nil {
			return nil, err
		}
		setTCPOptions(conn)
		return conn, nil
	}
	conn, err := net.DialTimeout("tcp", addr, defaultDialTimeout)
	if err != nil {
		return nil, err
	}
	setTCPOptions(conn)
	return conn, nil
}

// sendListen sends a listen request via the control stream.
func (c *Client) sendListen(port int, localAddr string) error {
	resp, err := c.sendControl(controlRequest{
		Type:          "listen",
		listenRequest: listenRequest{Port: port, LocalAddr: localAddr},
	})
	if err != nil {
		return fmt.Errorf("listen request: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("listen rejected: %s", resp.Error)
	}
	log.Printf("[vtunnel-client] Listen OK: port=%d", port)
	return nil
}

// sendListenWithDomain sends a listen request with port 0 (server auto-allocates)
// and a domain hint for proxy mapping. It parses the reply to learn the actual
// port and registers it in the forwards map.
//
// The server may rewrite LocalAddr in the reply (e.g. adding "tls://" prefix
// when MITM is active for :443 targets). If present, the rewritten address
// is used instead of the original — this enables client-side TLS termination
// so that MITM-decrypted plain HTTP is re-encrypted before reaching the target.
func (c *Client) sendListenWithDomain(localAddr, domain string) error {
	resp, err := c.sendControl(controlRequest{
		Type:          "listen",
		listenRequest: listenRequest{Port: 0, LocalAddr: localAddr, Domain: domain},
	})
	if err != nil {
		return fmt.Errorf("forward request: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("forward rejected: %s", resp.Error)
	}

	// Server replies with the allocated port and optionally a rewritten
	// LocalAddr (e.g. "tls://host:443" when MITM requires TLS wrapping).
	if resp.Port > 0 {
		addr := localAddr
		if resp.LocalAddr != "" {
			addr = resp.LocalAddr
		}
		c.mu.Lock()
		c.forwards[resp.Port] = addr
		c.mu.Unlock()
	}

	log.Printf("[vtunnel-client] Forward OK: %s (port=%d)", domain, resp.Port)
	return nil
}

func (c *Client) setSession(session *yamux.Session) {
	c.connMu.Lock()
	c.session = session
	c.connMu.Unlock()
}

func (c *Client) getSession() *yamux.Session {
	c.connMu.RLock()
	session := c.session
	c.connMu.RUnlock()
	return session
}

// connectOnce dials, sets the session, and replays forwards.
func (c *Client) connectOnce() error {
	session, err := c.dialOnce()
	if err != nil {
		return err
	}
	c.setSession(session)
	c.replayForwards()
	return nil
}

// connectionLoop waits for the current connection to die, then reconnects
// with exponential backoff. Runs until the client is closed.
func (c *Client) connectionLoop() {
	// Wait for current connection to die
	if session := c.getSession(); session != nil {
		<-session.CloseChan()
	}

	bo := c.newBackoff()
	for {
		if c.ctx.Err() != nil {
			return
		}

		err := c.connectOnce()
		if err != nil {
			delay := bo.NextBackOff()
			log.Printf("[vtunnel-client] Reconnect failed: %v (retrying in %v)", err, delay)
			select {
			case <-c.done:
				return
			case <-time.After(delay):
			}
			continue
		}

		bo.Reset()
		log.Printf("[vtunnel-client] Reconnected to %s", c.wsURL)

		// Block until this connection dies
		if session := c.getSession(); session != nil {
			<-session.CloseChan()
		}
	}
}

func (c *Client) replayForwards() {
	c.mu.RLock()
	fwds := make(map[int]string, len(c.forwards))
	for port, addr := range c.forwards {
		fwds[port] = addr
	}
	domFwds := make(map[string]string, len(c.domainForwards))
	for domain, addr := range c.domainForwards {
		domFwds[domain] = addr
	}
	c.mu.RUnlock()

	session := c.getSession()
	if session == nil {
		return
	}

	for port, addr := range fwds {
		if err := c.sendListen(port, addr); err != nil {
			log.Printf("[vtunnel-client] Re-listen failed for port %d: %v", port, err)
		}
	}

	for domain, addr := range domFwds {
		if err := c.sendListenWithDomain(addr, domain); err != nil {
			log.Printf("[vtunnel-client] Re-forward failed for %s: %v", domain, err)
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
