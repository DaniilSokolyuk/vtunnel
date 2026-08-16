package vtunnel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
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

	keepAlive    time.Duration
	reconnectMin time.Duration
	reconnectMax time.Duration
	authSigner   ssh.Signer // nil = no auth

	// proxy is the controlplane-side MITM proxy and the single place routes are
	// declared. It holds every target, header and the MITM CA — none of which
	// crosses the tunnel; the sandbox is told domain names and nothing else.
	// The sandbox router chains matching requests to it through routerPort.
	//
	// It listens on loopback because that is how tunnelled connections reach it:
	// an incoming SSH channel is piped into a fresh TCP connection to this
	// address. Nothing outside this process should ever dial it.
	proxy      *MITMProxy
	proxyStart sync.Once
	proxyErr   error
	// proxyOwned records that this client started the proxy, and may therefore
	// stop it. One handed in through [WithProxy] and already serving belongs to
	// the caller.
	proxyOwned bool
	routerPort int
}

// Option configures a Client.
type Option func(*Client)

// WithKeepAlive sets the keepalive ping interval (0 = default 30s, negative = disabled).
func WithKeepAlive(d time.Duration) Option {
	return func(c *Client) {
		c.keepAlive = d
	}
}

// WithPingInterval is a deprecated alias for [WithKeepAlive].
//
// Deprecated: use WithKeepAlive.
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

// WithMitm turns on TLS interception for forwarded domains, using ca to sign
// the certificates the proxy generates. This is the option to reach for:
//
//	client := vtunnel.NewClient(url, vtunnel.WithMitm(ca))
//	client.Forward("api.corp", "localhost:8081", vtunnel.WithHeader("Authorization", token))
//
// ca is the private key too, and it stays in this process — only its
// certificate half belongs in a sandbox trust store. Without this option the
// client still forwards domains, but their TLS is piped through untouched and
// no headers can be injected.
func WithMitm(ca tls.Certificate) Option {
	return func(c *Client) {
		c.proxy = NewMITMProxy(WithMitmCA(ca))
	}
}

// WithProxy replaces the client's controlplane proxy wholesale.
//
// [WithMitm] is the shorthand for the ordinary case — it is exactly:
//
//	WithProxy(NewMITMProxy(WithMitmCA(ca)))
//
// Reach for WithProxy only when that is not enough: to share one proxy between
// clients, to pre-load mappings instead of declaring them with
// [Client.Forward], or to pin its listening address:
//
//	p := NewMITMProxy(WithMitmCA(ca))
//	p.Start("127.0.0.1:8888") // already serving; the client leaves it alone
//	client := NewClient(url, WithProxy(p))
//
// Keep that address on loopback. The proxy injects credentials, and the tunnel
// reaches it from inside this process — no one else has any business dialing it.
func WithProxy(p *MITMProxy) Option {
	return func(c *Client) {
		c.proxy = p
	}
}

// ForwardOption configures a single call to Client.Forward.
type ForwardOption func(*forwardConfig)

type forwardConfig struct {
	headers http.Header
	sni     string
}

// WithSNI sets the server name the proxy presents when it opens TLS to the
// forward's target, for upstreams whose certificate does not name the address
// they are dialled at — behind a load balancer, or reached by IP.
//
//	proxy.ForwardTo("api.corp", "tls://10.0.0.7:443", vtunnel.WithSNI("api.corp"))
func WithSNI(host string) ForwardOption {
	return func(fc *forwardConfig) {
		fc.sni = host
	}
}

// WithHeader declares an HTTP header injected into every request this client
// proxies for the domain. Use multiple WithHeader calls to add several headers;
// repeating a name accumulates values (http.Header.Add semantics).
//
// Injection happens on this machine, after the request is decrypted, so it
// requires [WithMitm]; the header value never crosses the tunnel. The
// configured set overwrites any same-named header the sandbox application sent
// — the controlplane is authoritative.
func WithHeader(name, value string) ForwardOption {
	return func(fc *forwardConfig) {
		if fc.headers == nil {
			fc.headers = http.Header{}
		}
		fc.headers.Add(name, value)
	}
}

// NewClient creates a new vtunnel client.
func NewClient(wsURL string, opts ...Option) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		wsURL:        wsURL,
		forwards:     make(map[int]string),
		done:         make(chan struct{}),
		ctx:          ctx,
		cancel:       cancel,
		keepAlive:    defaultKeepAlive,
		reconnectMin: defaultReconnectMin,
		reconnectMax: defaultReconnectMax,
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.proxy == nil {
		c.proxy = NewMITMProxy()
	}
	// Refuse anything unrouted, unless the caller said otherwise.
	//
	// The tunnel port on the sandbox is pointed at this proxy as a whole, not at
	// one forward target, and a process inside the sandbox that dials that port
	// directly never passes through the Router or its allowlist. A proxy that
	// dials whatever it is asked for would then hand the sandbox the
	// controlplane's entire network — the cloud metadata endpoint included.
	// Dialling on demand is the right default for a sandbox-side proxy and the
	// wrong one here.
	if c.proxy.unmappedHandler() == nil {
		c.proxy.HandleUnmapped(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("[vtunnel-client] refused %s %s: not a forwarded domain", r.Method, r.Host)
			http.Error(w, "vtunnel: not a forwarded domain", http.StatusForbidden)
		}))
	}
	// Routes are declared on the proxy; the client's job is to keep the sandbox
	// in step with them. Subscribing here means a route added at any time — before
	// Connect, or long after — reaches the sandbox without a second call.
	c.proxy.OnChange(c.syncRoutes)

	if c.authSigner == nil {
		log.Println("[vtunnel-client] WARNING: No key configured. Authentication is DISABLED. Do NOT use in production! Use --key or VTUNNEL_KEY.")
	}
	return c
}

// Connect establishes a WebSocket+SSH connection to the server.
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

	sshConn := c.getSSH()
	if sshConn == nil {
		return nil // will be replayed on reconnect
	}

	return c.sendListen(sshConn, remotePort, localAddr)
}

// syncRoutes brings the sandbox router in step with the proxy's routes. It runs
// on connect and again whenever the proxy's routes change, which is how routes
// declared on the proxy reach the sandbox without a second API to call.
func (c *Client) syncRoutes() {
	if len(c.proxy.Routes()) == 0 {
		return
	}
	if err := c.startProxy(); err != nil {
		log.Printf("[vtunnel-client] %v", err)
		return
	}

	sshConn := c.getSSH()
	if sshConn == nil {
		return // replayed once connected
	}
	if err := c.sendRouterListen(sshConn); err != nil {
		log.Printf("[vtunnel-client] Route sync failed: %v", err)
	}
}

// Proxy returns the controlplane-side proxy. Routes are declared on it, and
// this client mirrors them into the sandbox:
//
//	client.Proxy().Handle("gitlab.corp", gitlabHandler)
//	client.Proxy().Forward("nexus.corp")
//
// Changes take effect immediately while connected, and are replayed on
// reconnect.
func (c *Client) Proxy() *MITMProxy { return c.proxy }

// startProxy brings the local proxy up once, on first use, on an ephemeral
// loopback port. A proxy supplied through [WithProxy] that is already serving
// is left alone, so pinning its address stays possible without an option that
// invites binding it to a public interface.
func (c *Client) startProxy() error {
	c.proxyStart.Do(func() {
		if c.proxy.Addr() != nil {
			return // already started by the caller
		}
		if err := c.proxy.Start("127.0.0.1:0"); err != nil {
			c.proxyErr = fmt.Errorf("start controlplane proxy: %w", err)
			return
		}
		c.proxyOwned = true
	})
	return c.proxyErr
}

// parseForwardTarget splits a forward target into a dialable address and, when
// the upstream speaks TLS, the hostname to use for SNI. An explicit "tls://"
// prefix and a bare ":443" target mean the same thing.
func parseForwardTarget(addr string) (target, tlsHost string, upstreamIsTLS bool) {
	if after, ok := strings.CutPrefix(addr, "tls://"); ok {
		host, _, err := net.SplitHostPort(after)
		if err != nil {
			return after, "", false
		}
		return after, host, true
	}
	if host, port, err := net.SplitHostPort(addr); err == nil && port == "443" {
		return addr, host, true
	}
	return addr, "", false
}

// domainKeys expands a forward domain into proxy mapping keys. A domain
// without a port covers both :80 and :443.
func domainKeys(domain string) []string {
	if _, _, err := net.SplitHostPort(domain); err != nil {
		return []string{net.JoinHostPort(domain, "80"), net.JoinHostPort(domain, "443")}
	}
	return []string{domain}
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

	// The proxy holds every configured credential and listens on loopback, so
	// leaving it up outlives the client it belonged to: the documented
	// `defer client.Close()` would leak a listener per client, and anything
	// local could still have headers injected on its behalf. Only the proxy
	// this client started is stopped — one handed in through [WithProxy] and
	// already serving belongs to the caller.
	if c.proxyOwned {
		c.proxy.Close()
	}
	return nil
}

// dialOnce establishes a single WS+SSH connection.
func (c *Client) dialOnce() (ssh.Conn, error) {
	dialer := websocket.Dialer{
		HandshakeTimeout: defaultHandshakeTimeout,
		ReadBufferSize:   wsBufferSize,
		WriteBufferSize:  wsBufferSize,
		// The controlplane is someone's laptop, which may only reach the
		// sandbox through a corporate proxy. gorilla's own DefaultDialer does
		// this; a zero Dialer would silently ignore the environment.
		Proxy: http.ProxyFromEnvironment,
	}
	wsConn, _, err := dialer.DialContext(c.ctx, c.wsURL, c.headers)
	if err != nil {
		return nil, err
	}

	conn := NewWSConn(wsConn)
	sshConfig := &ssh.ClientConfig{
		User:    "vtunnel",
		Timeout: defaultHandshakeTimeout,
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
		return conn, nil
	}
	conn, err := net.DialTimeout("tcp", addr, defaultDialTimeout)
	if err != nil {
		return nil, err
	}
	setTCPOptions(conn)
	return conn, nil
}

// sendListen sends a listen request via SSH.
func (c *Client) sendListen(sshConn ssh.Conn, port int, localAddr string) error {
	payload := marshalJSON(listenRequest{Port: port})
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

// sendRouterListen asks the server for one tunnel port serving every forwarded
// domain and points the sandbox router at it. Only domain names travel.
func (c *Client) sendRouterListen(sshConn ssh.Conn) error {
	domains := c.proxy.Routes()

	c.mu.RLock()
	port := c.routerPort
	c.mu.RUnlock()

	if len(domains) == 0 && port == 0 {
		return nil // nothing forwarded yet, and no route to clear
	}

	// The tunnel port is pointed at this address, so there is nothing to ask for
	// without one. Reached whenever startProxy failed earlier — a taken port, a
	// refused bind, a CA that would not load — and replayForwards came through
	// here anyway on the next reconnect. Dereferencing the nil took down the
	// whole controlplane: the reconnect goroutine has no recover.
	proxyAddr := c.proxy.Addr()
	if proxyAddr == nil {
		return fmt.Errorf("controlplane proxy is not listening, so the sandbox has nowhere to chain to")
	}
	sort.Strings(domains) // stable payload, easier to diff in logs

	payload := marshalJSON(listenRequest{Port: port, Domains: domains})
	ok, resp, err := sshConn.SendRequest("listen", true, payload)
	if err != nil {
		return fmt.Errorf("forward request: %w", err)
	}
	if !ok {
		// Drop the cached port. It is an ephemeral one the sandbox allocated
		// last time, and a rejection usually means it is gone or taken by
		// something else — asking for it again on every reconnect would keep
		// failing forever, silently sending every forwarded domain straight out
		// of the sandbox instead of through the tunnel.
		c.mu.Lock()
		delete(c.forwards, c.routerPort)
		c.routerPort = 0
		c.mu.Unlock()
		return fmt.Errorf("forward rejected: %s", string(resp))
	}

	var reply listenRequest
	if err := json.Unmarshal(resp, &reply); err == nil && reply.Port > 0 {
		c.mu.Lock()
		c.routerPort = reply.Port
		// Tunnel channels for this port are piped into the local proxy.
		c.forwards[reply.Port] = proxyAddr.String()
		c.mu.Unlock()
	}

	log.Printf("[vtunnel-client] Forward OK: %v (tunnel port=%d)", domains, reply.Port)
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

// connectOnce dials, sets the SSH connection, and replays forwards.
func (c *Client) connectOnce() error {
	conn, err := c.dialOnce()
	if err != nil {
		return err
	}
	c.setSSH(conn)
	c.replayForwards()
	return nil
}

// connectionLoop waits for the current connection to die, then reconnects
// with exponential backoff. Runs until the client is closed.
func (c *Client) connectionLoop() {
	// Wait for current connection to die
	if conn := c.getSSH(); conn != nil {
		conn.Wait()
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
		if conn := c.getSSH(); conn != nil {
			conn.Wait()
		}
	}
}

func (c *Client) replayForwards() {
	c.mu.RLock()
	fwds := make(map[int]string, len(c.forwards))
	for port, addr := range c.forwards {
		fwds[port] = addr
	}
	// Read under the same lock as the snapshot: it is written from
	// sendRouterListen on another goroutine.
	routerPort := c.routerPort
	c.mu.RUnlock()

	sshConn := c.getSSH()
	if sshConn == nil {
		return
	}
	for port, addr := range fwds {
		if port == routerPort {
			continue // replayed as one router listen below
		}
		if err := c.sendListen(sshConn, port, addr); err != nil {
			log.Printf("[vtunnel-client] Re-listen failed for port %d: %v", port, err)
		}
	}

	if len(c.proxy.Routes()) > 0 {
		if err := c.sendRouterListen(sshConn); err != nil {
			log.Printf("[vtunnel-client] Re-forward failed: %v", err)
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
