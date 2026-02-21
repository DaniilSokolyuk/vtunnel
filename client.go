package vtunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

const (
	defaultHandshakeTimeout = 60 * time.Second
	defaultDialTimeout      = 10 * time.Second
	defaultReconnectMin     = 1 * time.Second
	defaultReconnectMax     = 5 * time.Second
)

var ErrNotConnected = errors.New("vtunnel: not connected")

// Client connects to a vtunnel server and forwards connections.
type Client struct {
	wsURL     string
	headers   http.Header
	sshConn   ssh.Conn
	connMu    sync.RWMutex
	forwards  map[int]string // remotePort -> localAddr
	mu        sync.RWMutex
	done      chan struct{}
	closeOnce sync.Once
	ctx       context.Context
	cancel    context.CancelFunc

	keepAlive     time.Duration
	autoReconnect bool
	reconnectMin  time.Duration
	reconnectMax  time.Duration
	authSigner    ssh.Signer // nil = no auth
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

// WithKey sets the client private key for authentication ("vt-priv-...").
// When set, the client authenticates via SSH public key auth and
// verifies the server's identity using a derived host key.
func WithKey(privKey string) Option {
	return func(c *Client) {
		signer, err := parsePrivateKey(privKey)
		if err != nil {
			panic(fmt.Sprintf("vtunnel: invalid key: %v", err))
		}
		c.authSigner = signer
	}
}

// NewClient creates a new vtunnel client.
func NewClient(wsURL string, opts ...Option) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		wsURL:         wsURL,
		forwards:      make(map[int]string),
		done:          make(chan struct{}),
		ctx:           ctx,
		cancel:        cancel,
		keepAlive:     defaultKeepAlive,
		autoReconnect: false,
		reconnectMin:  defaultReconnectMin,
		reconnectMax:  defaultReconnectMax,
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.authSigner == nil {
		log.Println("[vtunnel-client] WARNING: No key configured. Authentication is DISABLED. Do NOT use in production! Use --key or VTUNNEL_KEY.")
	}
	return c
}

// Connect establishes a WebSocket+SSH connection to the server.
func (c *Client) Connect() error {
	sshConn, err := c.dialOnce()
	if err != nil {
		return err
	}
	c.setSSH(sshConn)
	c.replayForwards()

	if c.autoReconnect {
		go c.reconnectLoop(sshConn)
	} else {
		go c.waitAndClose(sshConn)
	}

	log.Printf("[vtunnel-client] Connected to %s", c.wsURL)
	return nil
}

// Listen requests the server to listen on a remote port and forward to local.
func (c *Client) Listen(remotePort int, localAddr string) error {
	c.mu.Lock()
	c.forwards[remotePort] = localAddr
	c.mu.Unlock()

	log.Printf("[vtunnel-client] Requesting listen: remote=%d -> local=%s", remotePort, localAddr)

	sshConn := c.getSSH()
	if sshConn == nil {
		if c.autoReconnect {
			return nil // will be replayed on reconnect
		}
		return ErrNotConnected
	}

	return c.sendListen(sshConn, remotePort, localAddr)
}

// Close closes the client and all connections.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		close(c.done)
	})

	sshConn := c.getSSH()
	if sshConn != nil {
		sshConn.Close()
		c.setSSH(nil)
	}
	return nil
}

// dialOnce establishes a single WS+SSH connection.
func (c *Client) dialOnce() (ssh.Conn, error) {
	dialer := websocket.Dialer{
		HandshakeTimeout: defaultHandshakeTimeout,
	}
	wsConn, _, err := dialer.DialContext(c.ctx, c.wsURL, c.headers)
	if err != nil {
		return nil, err
	}

	conn := NewWSConn(wsConn)
	sshConfig := &ssh.ClientConfig{
		User: "vtunnel",
	}
	if c.authSigner != nil {
		sshConfig.Auth = []ssh.AuthMethod{ssh.PublicKeys(c.authSigner)}
		hostSigner, err := deriveHostKey(c.authSigner.PublicKey())
		if err != nil {
			wsConn.Close()
			return nil, fmt.Errorf("derive host key: %w", err)
		}
		sshConfig.HostKeyCallback = ssh.FixedHostKey(hostSigner.PublicKey())
	} else {
		sshConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, "", sshConfig)
	if err != nil {
		wsConn.Close()
		return nil, fmt.Errorf("SSH handshake: %w", err)
	}

	// Accept tunnel channels from server
	go c.handleChannels(chans)
	// Handle server-initiated requests (ping/pong)
	go handleRequests(reqs)
	// Keepalive
	if c.keepAlive > 0 {
		go keepAliveLoop(sshConn, c.keepAlive)
	}

	return sshConn, nil
}

// handleChannels accepts incoming SSH channels of type "tunnel" from the server.
func (c *Client) handleChannels(chans <-chan ssh.NewChannel) {
	for ch := range chans {
		if ch.ChannelType() != "tunnel" {
			ch.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		go c.handleTunnel(ch)
	}
}

// handleTunnel accepts a tunnel channel and pipes to the local target.
func (c *Client) handleTunnel(ch ssh.NewChannel) {
	var req tunnelRequest
	if err := json.Unmarshal(ch.ExtraData(), &req); err != nil {
		ch.Reject(ssh.ConnectionFailed, "invalid tunnel request")
		return
	}

	c.mu.RLock()
	localAddr, ok := c.forwards[req.Port]
	c.mu.RUnlock()

	if !ok {
		log.Printf("[vtunnel-client] No forward for port %d", req.Port)
		ch.Reject(ssh.ConnectionFailed, "no forward for port")
		return
	}

	stream, reqs, err := ch.Accept()
	if err != nil {
		log.Printf("[vtunnel-client] Accept channel failed: %v", err)
		return
	}
	go ssh.DiscardRequests(reqs)

	localConn, err := c.dialTarget(localAddr)
	if err != nil {
		log.Printf("[vtunnel-client] Failed to connect to %s: %v", localAddr, err)
		stream.Close()
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
		return newHostRewriteConn(conn, host), nil
	}
	conn, err := net.DialTimeout("tcp", addr, defaultDialTimeout)
	if err != nil {
		return nil, err
	}
	setTCPOptions(conn)
	return conn, nil
}

// hostRewriteConn wraps a net.Conn and rewrites the HTTP Host header.
type hostRewriteConn struct {
	net.Conn
	host    string
	hostBin []byte
}

func newHostRewriteConn(conn net.Conn, host string) *hostRewriteConn {
	return &hostRewriteConn{
		Conn:    conn,
		host:    host,
		hostBin: []byte("Host: " + host + "\r\n"),
	}
}

func (c *hostRewriteConn) Write(p []byte) (int, error) {
	const prefix = "\r\nHost: "
	start := bytes.Index(p, []byte(prefix))
	if start == -1 {
		return c.Conn.Write(p)
	}
	valueStart := start + len(prefix)
	end := bytes.Index(p[valueStart:], []byte("\r\n"))
	if end == -1 {
		return c.Conn.Write(p)
	}
	var rewritten []byte
	rewritten = append(rewritten, p[:start+2]...)
	rewritten = append(rewritten, c.hostBin...)
	rewritten = append(rewritten, p[valueStart+end+2:]...)
	_, err := c.Conn.Write(rewritten)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// sendListen sends a listen request via SSH.
func (c *Client) sendListen(sshConn ssh.Conn, port int, localAddr string) error {
	payload := marshalJSON(listenRequest{Port: port, LocalAddr: localAddr})
	ok, resp, err := sshConn.SendRequest("listen", true, payload)
	if err != nil {
		return fmt.Errorf("listen request: %w", err)
	}
	if !ok {
		return fmt.Errorf("listen rejected: %s", string(resp))
	}
	log.Printf("[vtunnel-client] Listen OK: port=%d", port)
	return nil
}

func (c *Client) setSSH(conn ssh.Conn) {
	c.connMu.Lock()
	c.sshConn = conn
	c.connMu.Unlock()
}

func (c *Client) getSSH() ssh.Conn {
	c.connMu.RLock()
	conn := c.sshConn
	c.connMu.RUnlock()
	return conn
}

func (c *Client) waitAndClose(sshConn ssh.Conn) {
	sshConn.Wait()
	select {
	case <-c.done:
	default:
		c.Close()
	}
}

func (c *Client) reconnectLoop(sshConn ssh.Conn) {
	bo := c.newBackoff()

	// Wait for first connection to die
	sshConn.Wait()

	for {
		if c.ctx.Err() != nil {
			return
		}

		bo.Reset()
		for {
			if c.ctx.Err() != nil {
				return
			}

			conn, err := c.dialOnce()
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

			if c.ctx.Err() != nil {
				conn.Close()
				return
			}

			c.setSSH(conn)
			c.replayForwards()
			log.Printf("[vtunnel-client] Reconnected to %s", c.wsURL)

			// Block until this connection dies
			conn.Wait()
			break
		}
	}
}

func (c *Client) replayForwards() {
	c.mu.RLock()
	fwds := make(map[int]string, len(c.forwards))
	for port, addr := range c.forwards {
		fwds[port] = addr
	}
	c.mu.RUnlock()

	sshConn := c.getSSH()
	if sshConn == nil {
		return
	}

	for port, addr := range fwds {
		if err := c.sendListen(sshConn, port, addr); err != nil {
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
