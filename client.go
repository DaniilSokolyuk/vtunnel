package vtunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/gorilla/websocket"
	"golang.org/x/net/http2"
)

const (
	defaultHandshakeTimeout = 60 * time.Second
	defaultDialTimeout      = 10 * time.Second
	defaultReconnectMin     = 1 * time.Second
	defaultReconnectMax     = 5 * time.Second
	defaultPoolSize         = 8
)

// Client connects to a vtunnel server and forwards connections.
type Client struct {
	wsURL   string
	headers http.Header
	h2cc    *http2.ClientConn // current h2 connection over WS
	connMu  sync.RWMutex

	forwards map[int]string // remotePort -> localAddr
	mu       sync.RWMutex
	done     chan struct{}

	closeOnce sync.Once
	ctx       context.Context
	cancel    context.CancelFunc

	keepAlive    time.Duration
	reconnectMin time.Duration
	reconnectMax time.Duration
	privKey      ed25519.PrivateKey // nil = no auth
	poolSize     int

	// Domain-based forwards (Forward method)
	domainForwards map[string]string // domain -> localAddr

	// Connection lifecycle
	poolCancel context.CancelFunc // cancels the stream pool
	connDied   chan struct{}       // closed when h2cc dies
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
// When set, the client authenticates via ed25519 signed token in HTTP Authorization header.
func WithKey(privKey string) Option {
	return func(c *Client) {
		key, err := parsePrivateKey(privKey)
		if err != nil {
			panic(fmt.Sprintf("vtunnel: invalid key: %v", err))
		}
		c.privKey = key
	}
}

// WithPoolSize sets the tunnel stream pool size (default 8).
func WithPoolSize(n int) Option {
	return func(c *Client) {
		if n > 0 {
			c.poolSize = n
		}
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
		poolSize:       defaultPoolSize,
		connDied:       make(chan struct{}),
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.privKey == nil {
		log.Println("[vtunnel-client] WARNING: No key configured. Authentication is DISABLED. Do NOT use in production! Use --key or VTUNNEL_KEY.")
	}
	return c
}

// Connect establishes a WebSocket+h2mux connection to the server.
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

	cc := c.getH2CC()
	if cc == nil {
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

	cc := c.getH2CC()
	if cc == nil {
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

	c.connMu.Lock()
	if c.poolCancel != nil {
		c.poolCancel()
	}
	cc := c.h2cc
	c.h2cc = nil
	c.connMu.Unlock()

	if cc != nil {
		cc.Close()
	}
	return nil
}

// dialOnce establishes a single WS+h2mux connection.
func (c *Client) dialOnce() error {
	dialer := websocket.Dialer{
		HandshakeTimeout: defaultHandshakeTimeout,
	}
	wsConn, _, err := dialer.DialContext(c.ctx, c.wsURL, c.headers)
	if err != nil {
		return err
	}

	conn := NewWSConn(wsConn)

	// Create HTTP/2 client connection over the WebSocket
	h2t := &http2.Transport{}
	if c.keepAlive > 0 {
		h2t.ReadIdleTimeout = c.keepAlive
		// Scale PingTimeout to keepAlive: 3x the interval, capped at 15s.
		pingTimeout := c.keepAlive * 3
		if pingTimeout > 15*time.Second {
			pingTimeout = 15 * time.Second
		}
		h2t.PingTimeout = pingTimeout
	}

	h2cc, err := h2t.NewClientConn(conn)
	if err != nil {
		wsConn.Close()
		return fmt.Errorf("h2 client conn: %w", err)
	}

	// Cancel previous pool
	c.connMu.Lock()
	if c.poolCancel != nil {
		c.poolCancel()
	}
	c.h2cc = h2cc
	c.connDied = make(chan struct{})
	poolCtx, poolCancel := context.WithCancel(c.ctx)
	c.poolCancel = poolCancel
	c.connMu.Unlock()

	// Start tunnel stream pool
	go c.maintainStreamPool(poolCtx)

	return nil
}

func (c *Client) getH2CC() *http2.ClientConn {
	c.connMu.RLock()
	cc := c.h2cc
	c.connMu.RUnlock()
	return cc
}

// signalDeath signals that the h2 connection has died.
func (c *Client) signalDeath() {
	c.connMu.Lock()
	select {
	case <-c.connDied:
		// already signaled
	default:
		close(c.connDied)
	}
	c.connMu.Unlock()
}

// authToken generates the Authorization header value.
func (c *Client) authToken() string {
	return generateAuthToken(c.privKey)
}

// setAuthHeader sets the Authorization header if authentication is configured.
func (c *Client) setAuthHeader(req *http.Request) {
	if token := c.authToken(); token != "" {
		req.Header.Set("Authorization", token)
	}
}

// doRoundTrip performs an HTTP/2 round trip, signaling death on connection errors.
func (c *Client) doRoundTrip(req *http.Request) (*http.Response, error) {
	cc := c.getH2CC()
	if cc == nil {
		return nil, fmt.Errorf("not connected")
	}

	resp, err := cc.RoundTrip(req)
	if err != nil {
		c.signalDeath()
		return nil, err
	}
	return resp, nil
}

// sendControl sends a control request (listen/forward) to the server and returns the response.
func (c *Client) sendControl(endpoint string, lr listenRequest) (listenResponse, error) {
	body, _ := json.Marshal(lr)
	req, _ := http.NewRequest("POST", "http://vtunnel/"+endpoint, bytes.NewReader(body))
	c.setAuthHeader(req)

	resp, err := c.doRoundTrip(req)
	if err != nil {
		return listenResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return listenResponse{}, fmt.Errorf("authentication failed")
	}

	var result listenResponse
	json.NewDecoder(resp.Body).Decode(&result)
	if !result.OK {
		return result, fmt.Errorf("%s rejected: %s", endpoint, result.Error)
	}
	return result, nil
}

// sendListen sends a listen request to the server.
func (c *Client) sendListen(port int, localAddr string) error {
	_, err := c.sendControl("listen", listenRequest{Port: port, LocalAddr: localAddr})
	if err != nil {
		return err
	}
	log.Printf("[vtunnel-client] Listen OK: port=%d", port)
	return nil
}

// sendListenWithDomain sends a listen request with port 0 (server auto-allocates)
// and a domain hint for proxy mapping. It parses the reply to learn the actual
// port and registers it in the forwards map.
func (c *Client) sendListenWithDomain(localAddr, domain string) error {
	result, err := c.sendControl("forward", listenRequest{Port: 0, LocalAddr: localAddr, Domain: domain})
	if err != nil {
		return err
	}

	// Server replies with the allocated port and optionally a rewritten LocalAddr.
	if result.Port > 0 {
		addr := localAddr
		if result.LocalAddr != "" {
			addr = result.LocalAddr
		}
		c.mu.Lock()
		c.forwards[result.Port] = addr
		c.mu.Unlock()
	}

	log.Printf("[vtunnel-client] Forward OK: %s (port=%d)", domain, result.Port)
	return nil
}

// openTunnelStream opens one long-polling tunnel stream.
// Blocks until the server assigns tunnel traffic or the context is canceled.
func (c *Client) openTunnelStream(ctx context.Context) error {
	cc := c.getH2CC()
	if cc == nil {
		return fmt.Errorf("not connected")
	}

	pr, pw := io.Pipe()
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://vtunnel/tunnel", pr)
	c.setAuthHeader(req)

	resp, err := cc.RoundTrip(req) // blocks until server assigns traffic
	if err != nil {
		pw.Close()
		c.signalDeath()
		return err
	}
	defer resp.Body.Close()
	defer pw.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("authentication failed")
	}

	port, _ := strconv.Atoi(resp.Header.Get("X-Tunnel-Port"))

	c.mu.RLock()
	localAddr, ok := c.forwards[port]
	c.mu.RUnlock()

	if !ok {
		log.Printf("[vtunnel-client] No forward for port %d", port)
		return fmt.Errorf("no forward for port %d", port)
	}

	localConn, err := c.dialTarget(localAddr)
	if err != nil {
		log.Printf("[vtunnel-client] Failed to connect to %s: %v", localAddr, err)
		return err
	}

	log.Printf("[vtunnel-client] New tunnel: port=%d -> %s", port, localAddr)
	stream := &h2ClientStream{body: resp.Body, pw: pw}
	pipe(stream, localConn)
	return nil
}

// h2ClientStream wraps an HTTP/2 response body (read from server) and a pipe writer (write to server).
type h2ClientStream struct {
	body io.ReadCloser  // resp.Body — reads data from server
	pw   *io.PipeWriter // writes data to server via request body
}

func (s *h2ClientStream) Read(p []byte) (int, error)  { return s.body.Read(p) }
func (s *h2ClientStream) Write(p []byte) (int, error) { return s.pw.Write(p) }
func (s *h2ClientStream) Close() error {
	s.pw.Close()
	return s.body.Close()
}

// maintainStreamPool maintains N concurrent tunnel streams.
// When one completes, a new one is opened to refill the pool.
func (c *Client) maintainStreamPool(ctx context.Context) {
	sem := make(chan struct{}, c.poolSize)
	for {
		select {
		case <-ctx.Done():
			return
		case sem <- struct{}{}:
		}
		go func() {
			defer func() { <-sem }()
			if err := c.openTunnelStream(ctx); err != nil {
				if ctx.Err() == nil {
					log.Printf("[vtunnel-client] Tunnel stream error: %v", err)
				}
			}
		}()
	}
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

// connectOnce dials, replays forwards, and starts the stream pool.
func (c *Client) connectOnce() error {
	if err := c.dialOnce(); err != nil {
		return err
	}
	c.replayForwards()
	return nil
}

// waitForDeath blocks until the h2 connection dies or the client is closed.
// Returns false if the client is shutting down.
func (c *Client) waitForDeath() bool {
	c.connMu.RLock()
	died := c.connDied
	c.connMu.RUnlock()
	select {
	case <-died:
		c.connMu.Lock()
		if c.poolCancel != nil {
			c.poolCancel()
		}
		c.connMu.Unlock()
		return true
	case <-c.done:
		return false
	}
}

// connectionLoop waits for the current connection to die, then reconnects
// with exponential backoff. Runs until the client is closed.
func (c *Client) connectionLoop() {
	if !c.waitForDeath() {
		return
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

		if !c.waitForDeath() {
			return
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
