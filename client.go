package vtunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/vivid-money/vtunnel/internal/session"
	"github.com/vivid-money/vtunnel/internal/tunnelkey"
)

const (
	defaultHandshakeTimeout = 60 * time.Second
	defaultDialTimeout      = 10 * time.Second
	defaultReconnectMin     = 1 * time.Second
	defaultReconnectMax     = 5 * time.Second
)

// Client connects to a vtunnel server and forwards connections.
type Client struct {
	url          string
	dialer       Dialer
	protocol     Protocol
	streamWindow int
	sess         session.Session
	connMu       sync.RWMutex
	forwards     map[int]string // remotePort -> localAddr
	mu           sync.RWMutex
	done         chan struct{}
	closeOnce    sync.Once
	ctx          context.Context
	cancel       context.CancelFunc

	keepAlive    time.Duration
	reconnectMin time.Duration
	reconnectMax time.Duration

	// keys authenticates both ends; nil means the tunnel is unauthenticated.
	keys *tunnelkey.Keys

	// proxy is the controlplane-side MITM proxy and the single place routes are
	// declared. It holds every target, header and the MITM CA — none of which
	// crosses the tunnel; the sandbox is told domain names and nothing else.
	// The sandbox egress proxy chains matching requests to it through egressPort.
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
	//
	// Atomic because the two ends of it are on different goroutines: it is set
	// by startProxy, which runs on whoever declared a route, and read by Close,
	// on the owner's.
	proxyOwned atomic.Bool
	egressPort int

	// egressPolicy is what the sandbox may reach on its own. Guarded by mu, and
	// replayed on every reconnect: a sandbox that came back, or came up fresh,
	// knows nothing until it is told again.
	egressPolicy *Policy
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

// WithReconnectBackoff configures the reconnect backoff window.
func WithReconnectBackoff(min, max time.Duration) Option {
	return func(c *Client) {
		c.reconnectMin = min
		c.reconnectMax = max
	}
}

// WithSecret sets the tunnel secret, the one value that authenticates this
// client and the server to each other. The sandbox must be given the same
// secret through [WithServerSecret].
//
// Any string will do — 32 random bytes, a token from a secret manager, a UUID
// an orchestrator minted for one sandbox. There is no format, because a format
// would prove nothing about the only property that matters, which is that
// nobody else can guess it. A short or obviously public one is taken anyway and
// warned about.
//
// Both identities are derived from it, so the client both proves itself and
// pins the host key it will accept. Generate one per sandbox: the secret is
// symmetric, so whoever holds it can be either end, and one shared across a
// fleet makes any single compromised sandbox able to pose as all of them.
//
// An empty secret leaves the tunnel unauthenticated in both directions, and
// [NewClient] says so.
func WithSecret(secret string) Option {
	return func(c *Client) {
		if secret == "" {
			return
		}
		if w := tunnelkey.Warning(secret); w != "" {
			log.Printf("[vtunnel-client] WARNING: %s.", w)
		}
		keys, err := tunnelkey.Derive(secret)
		if err != nil {
			panic(fmt.Sprintf("vtunnel: derive tunnel keys: %v", err))
		}
		c.keys = keys
	}
}

// WithDialer replaces the transport with one of your own, and is where
// anything transport-shaped is configured. Headers on the WebSocket handshake,
// for a corporate proxy in the way, are a property of that WebSocket rather
// than of the tunnel, so they are set on the dialer that opens it:
//
//	d, err := vtunnel.NewDialer("wss://sandbox:3001/", http.Header{
//	    "Proxy-Authorization": {"Basic " + creds},
//	})
//	client := vtunnel.NewClient("wss://sandbox:3001/",
//	    vtunnel.WithDialer(d), vtunnel.WithSecret(secret))
//
// Wrapping [NewDialer] is the way to add behaviour the tunnel has no opinion
// about — a retry, a dial through something else, artificial latency for a
// benchmark. The URL passed to [NewClient] is then only a label for logs.
//
// Reaching a sandbox over TCP instead of a WebSocket needs no option at all —
// see [NewClient].
func WithDialer(d Dialer) Option {
	return func(c *Client) {
		c.dialer = d
	}
}

// WithProtocol picks the session protocol. The sandbox must be configured with
// the same one through [WithServerProtocol]; see [Protocol].
func WithProtocol(p Protocol) Option {
	return func(c *Client) {
		c.protocol = p
	}
}

// WithStreamWindow sets how much the sandbox may send into one tunnelled
// connection before this client has acknowledged any of it. Zero keeps the
// default of 8 MB.
//
// It is a speed limit wearing the clothes of a buffer size: one connection can
// go no faster than the window divided by the round trip, and bandwidth does
// not enter into it. Raise it for a distant sandbox moving large objects; lower
// it if many connections are open at once and memory is tight. The window is an
// allowance rather than memory reserved — yamux buffers only while the local
// reader falls behind — but a stalled target can hold the whole of it, per
// connection.
//
// To put numbers on your own link, cmd/bench takes -window and -latency.
//
// This governs sandbox to controlplane. The other direction is the sandbox's to
// set, with [WithServerStreamWindow], and raising only one of them raises only
// one of them. [ProtocolSSH] ignores both: golang.org/x/crypto/ssh fixes the
// window at 2 MB and offers no way to ask for more, which is the concrete
// reason the other protocols exist.
func WithStreamWindow(bytes int) Option {
	return func(c *Client) {
		c.streamWindow = bytes
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
	target  string
}

// WithTarget sends the domain somewhere other than where it already points.
// Without it a route goes to the host the request named, which is what lets one
// wildcard stand for a family of hosts, each reaching itself.
//
// The target is a "host[:port]", optionally prefixed with "tls://", "h2c://" or
// "http://" to state how the upstream is spoken to rather than leaving it to be
// discovered. Written without a port it is dialled on the port the client asked
// for, and follows the client on protocol too; see [MITMProxy.ForwardTo], which
// is this option with the target where a reader expects to find it.
//
//	proxy.Forward("api.corp", vtunnel.WithTarget("localhost:8081"))
//	proxy.Forward("*.corp", vtunnel.WithTarget("gw.internal")) // all of them, one gateway
func WithTarget(target string) ForwardOption {
	return func(fc *forwardConfig) {
		fc.target = target
	}
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
//
// tunnelURL says both where the sandbox is and how to reach it: the scheme
// picks the transport, and ws, wss and tcp are understood.
//
//	vtunnel.NewClient("wss://sandbox.example.com/", vtunnel.WithSecret(secret))
//	vtunnel.NewClient("tcp://sandbox:3001", vtunnel.WithSecret(secret))
//
// Which one changes nothing about how safe the tunnel is — the session
// authenticates the sandbox and encrypts the traffic either way. Anything the
// schemes do not cover is [WithDialer].
//
// An unusable URL is not reported here; [Client.Connect] returns it.
func NewClient(tunnelURL string, opts ...Option) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		url:          tunnelURL,
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
	// directly never passes through the EgressProxy or its allowlist. A proxy that
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

	if c.protocol.insecure() {
		log.Printf("[vtunnel-client] WARNING: protocol %q has no encryption and no authentication. "+
			"Any secret configured is ignored, and whoever answers this dial can pipe streams "+
			"into every local target — the credential-injecting proxy included. "+
			"It is here to be measured against, not to be run.", c.protocol)
	} else if c.keys == nil {
		log.Println("[vtunnel-client] WARNING: No tunnel secret configured. Authentication is DISABLED. Do NOT use in production! Use --secret or VTUNNEL_SECRET.")
	}
	return c
}

// Connect establishes a WebSocket+SSH connection to the server.
func (c *Client) Connect() error {
	if err := c.connectOnce(); err != nil {
		return err
	}
	log.Printf("[vtunnel-client] Connected to %s", c.url)
	go c.connectionLoop()
	return nil
}

// Listen requests the server to listen on a remote port and forward to local.
//
// remotePort must be a real port. Zero — "let the sandbox pick" — is refused:
// the port exists for something inside the sandbox to connect to, so a port
// only the sandbox knows is a port nobody can use. It was accepted once, and
// quietly did nothing: the sandbox allocated an ephemeral port and reported it,
// the answer was dropped, and every tunnel stream for the forward arrived
// tagged with a port this client had never heard of.
func (c *Client) Listen(remotePort int, localAddr string) error {
	if remotePort <= 0 || remotePort > 65535 {
		return fmt.Errorf("vtunnel: Listen needs a fixed remote port in 1..65535, got %d", remotePort)
	}

	c.mu.Lock()
	c.forwards[remotePort] = localAddr
	c.mu.Unlock()

	log.Printf("[vtunnel-client] Requesting listen: remote=%d -> local=%s", remotePort, localAddr)

	sess := c.getSession()
	if sess == nil {
		return nil // will be replayed on reconnect
	}

	return c.sendListen(sess, remotePort, localAddr)
}

// syncRoutes brings the sandbox egress proxy in step with the proxy's routes. It runs
// on connect and again whenever the proxy's routes change, which is how routes
// declared on the proxy reach the sandbox without a second API to call.
func (c *Client) syncRoutes() {
	c.mu.RLock()
	egressPort := c.egressPort
	c.mu.RUnlock()

	// No routes and none ever announced: nothing for the sandbox to hear about.
	// With an egress proxy port already open the empty list is the message — it is how
	// the last forward is withdrawn. Returning here instead left the sandbox
	// chaining a domain into a controlplane that had forgotten it, answering 403
	// for as long as the tunnel lived.
	if len(c.proxy.Routes()) == 0 && egressPort == 0 {
		return
	}
	if err := c.startProxy(); err != nil {
		log.Printf("[vtunnel-client] %v", err)
		return
	}

	sess := c.getSession()
	if sess == nil {
		return // replayed once connected
	}
	if err := c.sendEgressListen(sess); err != nil {
		log.Printf("[vtunnel-client] Route sync failed: %v", err)
	}
}

// SetEgressPolicy tells the sandbox what it may reach without crossing the
// tunnel: a default, and the exceptions to it. See [Policy].
//
// It takes effect immediately when connected and is replayed on every
// reconnect, because a sandbox that comes back is a sandbox that has to be told
// again — and on a fresh sandbox process there is nothing to tell it otherwise.
// Passing a policy with no rules and [ActionAllow] is how it is withdrawn.
//
// The rules are parsed here before they are sent, so a typo is an error the
// caller gets back rather than one the sandbox reports to a log nobody is
// reading. A sandbox too old to understand the message is also an error: it
// would go on with open egress while this end believed otherwise.
//
// It governs the sandbox's own egress and nothing else. What the controlplane
// dials on the sandbox's behalf — the targets behind [MITMProxy.ForwardTo] — is
// governed by the routes declared there, and by [MITMProxy.HandleUnmapped].
func (c *Client) SetEgressPolicy(p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}

	c.mu.Lock()
	c.egressPolicy = &p
	c.mu.Unlock()

	sess := c.getSession()
	if sess == nil {
		return nil // replayed once connected
	}
	return c.sendPolicy(sess)
}

// sendPolicy hands the current policy to the sandbox.
func (c *Client) sendPolicy(sess session.Session) error {
	c.mu.RLock()
	p := c.egressPolicy
	c.mu.RUnlock()
	if p == nil {
		return nil
	}

	reply, err := request(sess, streamHeader{Type: streamPolicy, Policy: newWirePolicy(*p)})
	if err != nil {
		return fmt.Errorf("egress policy: %w", err)
	}
	if !reply.OK {
		return fmt.Errorf("egress policy rejected: %s", reply.Error)
	}
	if !reply.PolicyApplied {
		// It answered, and it answered the wrong question. Everything else in
		// this protocol can be read as "the sandbox did what was asked"; this
		// cannot, and reading it that way would mean believing a sandbox is
		// contained while it egresses freely.
		return fmt.Errorf("the sandbox acknowledged the request but not the policy: " +
			"it is too old to understand one, and its egress is unrestricted")
	}
	log.Printf("[vtunnel-client] Egress policy applied: default %s, %d allow, %d deny",
		p.Default, len(p.Allow), len(p.Deny))
	return nil
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
		c.proxyOwned.Store(true)
	})
	return c.proxyErr
}

// forwardTarget is a route target read into its parts: where to dial, how to
// speak to it, and whether the port is still to be decided.
type forwardTarget struct {
	// host is what to dial. It carries a port only when the target was written
	// with one; otherwise it is a bare host, with the brackets already off an
	// IPv6 literal so that net.JoinHostPort can put them back.
	host string
	// tlsHost is the server name to present when opening TLS to host, and is
	// empty when the hop is not TLS.
	tlsHost string
	// portFromRequest says the target named no port, so the port dialled is the
	// one the client asked for. A scheme states how to speak to an upstream and
	// not where it is, so none of them fills a port in.
	portFromRequest bool
	// h2c records that "h2c://" was written: cleartext HTTP/2, without asking.
	h2c bool
}

// parseRouteTarget reads the target of a domain route.
//
// Three schemes, and each exists to replace a guess with a statement:
//
//	tls://host[:port]   TLS, SNI from the host.
//	h2c://host[:port]   cleartext HTTP/2, so nothing is probed for it.
//	http://host[:port]  cleartext, and do not ask.
//
// Everything else is a bare address, about which the proxy asks the upstream
// rather than reading its intentions off a port number — except ":443", which
// says TLS as plainly as the prefix does.
//
// The port is optional throughout, and a target without one is dialled on the
// port the client asked for. That is what lets one route cover a host rather
// than a host and a port: "api.corp=gw.internal" reaches gw.internal on
// whatever port was asked for, where "gw.internal:8080" pins every one of them
// to 8080.
//
// A target that names no host is no target: an empty host is dialable in Go and
// means this machine, so "tls://", "tls://:0" and a bare ":443" are all refused
// rather than becoming a quiet connection to a local port — with, on a route
// configured for one, the credential attached. Found by
// FuzzForwardTargetIsCoherent.
func parseRouteTarget(addr string) (forwardTarget, bool) {
	t, ok := readForwardTarget(addr)
	if !ok {
		return forwardTarget{}, false
	}

	// A scheme that survived the strip means there was a second one behind it —
	// "tls://tls://" left "tls://" to be dialled as a hostname.
	if strings.Contains(t.host, "://") {
		return forwardTarget{}, false
	}
	if t.portFromRequest {
		// The host is the whole of the address, so it is the whole of the check —
		// and it has to survive the JoinHostPort that will put a port on it. A
		// stray bracket produced "]0:443", which is not an address and would
		// have been discovered as a failed dial.
		if t.host == "" {
			return forwardTarget{}, false
		}
		if host, _, err := net.SplitHostPort(net.JoinHostPort(t.host, "0")); err != nil || host != t.host {
			return forwardTarget{}, false
		}
		return t, true
	}
	if host, _, err := net.SplitHostPort(t.host); err != nil || host == "" {
		return forwardTarget{}, false
	}
	return t, true
}

// readForwardTarget is parseRouteTarget without the check that the result names
// somewhere. Split out so that check is written once, on every shape, rather
// than per branch — which is how the shapes that lacked it got missed.
func readForwardTarget(addr string) (forwardTarget, bool) {
	if after, ok := strings.CutPrefix(addr, "tls://"); ok {
		host, fromRequest := splitTargetPort(after)
		// The prefix says TLS whether or not a port came with it. Reading a
		// missing port as "not TLS after all" dropped the one thing the prefix
		// was there to say, and the request went out in the clear — with the
		// configured credential attached to it.
		return forwardTarget{
			host:            host,
			tlsHost:         hostFromAuthority(host),
			portFromRequest: fromRequest,
		}, host != ""
	}
	if after, ok := strings.CutPrefix(addr, "h2c://"); ok {
		// Cleartext HTTP/2, said outright. The proxy can find this by asking —
		// see MITMProxy.probeH2C — but asking costs a dial and a wait for the
		// peer's SETTINGS on the first request, and it is only ever asked when
		// the client side is HTTP/2 as well. Stating it skips both: an h2c
		// upstream stays h2c even for an HTTP/1.1 client, which is the one case
		// the probe cannot reach.
		host, fromRequest := splitTargetPort(after)
		return forwardTarget{host: host, portFromRequest: fromRequest, h2c: true}, host != ""
	}
	if after, ok := strings.CutPrefix(addr, "http://"); ok {
		// Said outright: reach this one in the clear, do not ask.
		host, fromRequest := splitTargetPort(after)
		return forwardTarget{host: host, portFromRequest: fromRequest}, host != ""
	}
	if host, port, err := net.SplitHostPort(addr); err == nil && port == "443" {
		return forwardTarget{host: addr, tlsHost: host}, true
	}
	// No scheme and no well-known port. Whether this upstream speaks TLS is
	// decided by asking it — see MITMProxy.upstreamTLSName — because reading it
	// off the port number is what sent a credential to an HTTPS backend on 8443
	// in plaintext.
	host, fromRequest := splitTargetPort(addr)
	return forwardTarget{host: host, portFromRequest: fromRequest}, host != ""
}

// splitTargetPort reports the address to dial and whether a port still has to
// be found for it. With no port written it takes the brackets off an IPv6
// literal, since net.JoinHostPort is what puts them back and "[[::1]]:443" is
// not an address anything can dial.
func splitTargetPort(addr string) (host string, portFromRequest bool) {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr, false
	}
	return strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]"), true
}

// parsePipeTarget reads the target of a raw port forward, where "tls://" is the
// only scheme that means anything: the pipe parses nothing, so there is nothing
// else to state.
//
// It is also the one place a missing port becomes 443 rather than the port the
// client asked for. The left side of a port forward is the port being listened
// on, not a destination, so there is no requested port to follow.
func parsePipeTarget(addr string) (target, tlsHost string, ok bool) {
	t, ok := parseRouteTarget(addr)
	if !ok || t.tlsHost == "" {
		return "", "", false
	}
	if !t.portFromRequest {
		return t.host, t.tlsHost, true
	}
	// parseRouteTarget has already established that this host survives having a
	// port joined onto it, so what comes out here is dialable.
	return net.JoinHostPort(t.host, "443"), t.tlsHost, true
}

// Close closes the client and all connections.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		close(c.done)
	})

	// Taken and cleared in one step, rather than through setSession: done is
	// closed by now, so setSession would refuse to write and leave the field
	// pointing at a session this call has just closed.
	c.connMu.Lock()
	sess := c.sess
	c.sess = nil
	c.connMu.Unlock()
	if sess != nil {
		sess.Close()
	}

	// The proxy holds every configured credential and listens on loopback, so
	// leaving it up outlives the client it belonged to: the documented
	// `defer client.Close()` would leak a listener per client, and anything
	// local could still have headers injected on its behalf. Only the proxy
	// this client started is stopped — one handed in through [WithProxy] and
	// already serving belongs to the caller.
	if c.proxyOwned.Load() {
		c.proxy.Close()
	}
	return nil
}

// transport resolves the dialer once, from [WithDialer] if one was given and
// otherwise from the scheme of the URL passed to [NewClient].
func (c *Client) transport() (Dialer, error) {
	if c.dialer != nil {
		return c.dialer, nil
	}
	d, err := NewDialer(c.url, nil)
	if err != nil {
		return nil, err
	}
	c.dialer = d
	return d, nil
}

// dialOnce brings up one transport connection and one session over it.
func (c *Client) dialOnce() (session.Session, error) {
	dial, err := c.transport()
	if err != nil {
		return nil, err
	}
	conn, err := dial(c.ctx)
	if err != nil {
		return nil, err
	}

	sess, err := session.Dial(session.Kind(c.protocol), conn, session.Config{
		Keys:         c.keys,
		Handshake:    defaultHandshakeTimeout,
		StreamWindow: c.streamWindow,
	})
	if err != nil {
		return nil, err
	}

	go serveStreams(sess, c.handleStream)
	if c.keepAlive > 0 {
		go keepAliveLoop(sess, c.keepAlive)
	}
	return sess, nil
}

// handleStream pipes a tunnel stream from the sandbox into its local target.
// Ping is already answered by serveStreams; the controlplane offers nothing
// else the sandbox may ask for.
func (c *Client) handleStream(stream net.Conn, h streamHeader) {
	if h.Type != streamTunnel {
		log.Printf("[vtunnel-client] Unknown stream type %q", h.Type)
		stream.Close()
		return
	}

	c.mu.RLock()
	localAddr, ok := c.forwards[h.Port]
	c.mu.RUnlock()

	if !ok {
		log.Printf("[vtunnel-client] No forward for port %d", h.Port)
		stream.Close()
		return
	}

	localConn, err := c.dialTarget(localAddr)
	if err != nil {
		log.Printf("[vtunnel-client] Failed to connect to %s: %v", localAddr, err)
		stream.Close()
		return
	}

	log.Printf("[vtunnel-client] New tunnel: port=%d -> %s", h.Port, localAddr)
	pipe(stream, localConn)
}

// dialTarget dials the target address; if it has a "tls://" prefix,
// a TLS connection is established with the appropriate ServerName.
func (c *Client) dialTarget(addr string) (net.Conn, error) {
	if strings.HasPrefix(addr, "tls://") {
		// parsePipeTarget, not the route reader: the prefix is the instruction,
		// and here a missing port is 443 rather than something to take from a
		// request this pipe never sees.
		target, host, ok := parsePipeTarget(addr)
		if !ok {
			return nil, fmt.Errorf("vtunnel: forward target %q names no host", addr)
		}
		dialer := &net.Dialer{Timeout: defaultDialTimeout}
		conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{ServerName: host})
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

// sendListen asks the sandbox to open a port and tunnel it here.
func (c *Client) sendListen(sess session.Session, port int, localAddr string) error {
	reply, err := request(sess, streamHeader{Type: streamListen, Port: port})
	if err != nil {
		return fmt.Errorf("listen request: %w", err)
	}
	if !reply.OK {
		return fmt.Errorf("listen rejected: %s", reply.Error)
	}
	// The local address stays on this side: the sandbox opens a port and pipes
	// it, and where the far end of that pipe goes is nobody's business but this
	// process's. It is logged so the two halves of a forward read as a pair.
	log.Printf("[vtunnel-client] Listen OK: sandbox port=%d -> %s", port, localAddr)
	return nil
}

// sendEgressListen asks the server for one tunnel port serving every forwarded
// domain and points the sandbox egress proxy at it. Only domain names travel.
func (c *Client) sendEgressListen(sess session.Session) error {
	domains := c.proxy.Routes()

	c.mu.RLock()
	port := c.egressPort
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

	reply, err := request(sess, streamHeader{Type: streamListen, Port: port, Domains: domains})
	if err != nil {
		return fmt.Errorf("forward request: %w", err)
	}
	if !reply.OK {
		// Drop the cached port. It is an ephemeral one the sandbox allocated
		// last time, and a rejection usually means it is gone or taken by
		// something else — asking for it again on every reconnect would keep
		// failing forever, silently sending every forwarded domain straight out
		// of the sandbox instead of through the tunnel.
		c.mu.Lock()
		delete(c.forwards, c.egressPort)
		c.egressPort = 0
		c.mu.Unlock()
		return fmt.Errorf("forward rejected: %s", reply.Error)
	}

	if reply.Port > 0 {
		c.mu.Lock()
		c.egressPort = reply.Port
		// Tunnel streams for this port are piped into the local proxy.
		c.forwards[reply.Port] = proxyAddr.String()
		c.mu.Unlock()
	}

	log.Printf("[vtunnel-client] Forward OK: %v (tunnel port=%d)", domains, reply.Port)
	return nil
}

// setSession publishes a session, unless the client has been closed in the
// meantime — in which case the session is closed instead of published.
//
// A reconnect already under way when Close is called finishes afterwards, and
// used to hand its session to a client nobody holds any more: a live tunnel
// with a stream loop and a keepalive behind it, and a reconnect loop ready to
// build another one as soon as it died. The owner had every reason to believe
// all of it was gone.
func (c *Client) setSession(sess session.Session) {
	c.connMu.Lock()
	select {
	case <-c.done:
		c.connMu.Unlock()
		if sess != nil {
			sess.Close()
		}
		return
	default:
	}
	c.sess = sess
	c.connMu.Unlock()
}

func (c *Client) getSession() session.Session {
	c.connMu.RLock()
	sess := c.sess
	c.connMu.RUnlock()
	return sess
}

// connectOnce dials, publishes the session, and replays forwards.
func (c *Client) connectOnce() error {
	conn, err := c.dialOnce()
	if err != nil {
		return err
	}
	c.setSession(conn)
	c.replayForwards()
	return nil
}

// connectionLoop waits for the current connection to die, then reconnects
// with exponential backoff. Runs until the client is closed.
func (c *Client) connectionLoop() {
	// Wait for current connection to die
	if conn := c.getSession(); conn != nil {
		conn.Wait()
	}

	bo := c.newBackoff()
	for {
		if c.ctx.Err() != nil {
			return
		}

		started := time.Now()
		err := c.connectOnce()
		if err == nil {
			log.Printf("[vtunnel-client] Reconnected to %s", c.url)

			// Block until this connection dies
			if conn := c.getSession(); conn != nil {
				conn.Wait()
			}

			// A session that lasted is what the backoff is reset for, and the
			// next attempt goes out immediately. Resetting on the mere fact of
			// having built one turned an endpoint that accepts and hangs up
			// straight away — a half-started sandbox, something answering for
			// one that has gone — into a spin: connect, die, connect, die,
			// with no delay anywhere and a core to itself.
			if time.Since(started) >= c.stableSession() {
				bo.Reset()
				continue
			}
			log.Printf("[vtunnel-client] Connection to %s ended after %v", c.url, time.Since(started).Round(time.Millisecond))
		} else {
			log.Printf("[vtunnel-client] Reconnect failed: %v", err)
		}

		delay := bo.NextBackOff()
		log.Printf("[vtunnel-client] Retrying in %v", delay)
		select {
		case <-c.done:
			return
		case <-time.After(delay):
		}
	}
}

// stableSession is how long a session has to last to count as one that worked.
// The longest backoff is the natural mark: anything shorter than the delay the
// retries would have grown to says nothing was achieved by connecting.
func (c *Client) stableSession() time.Duration {
	if c.reconnectMax > 0 {
		return c.reconnectMax
	}
	return defaultReconnectMax
}

func (c *Client) replayForwards() {
	c.mu.RLock()
	fwds := make(map[int]string, len(c.forwards))
	for port, addr := range c.forwards {
		fwds[port] = addr
	}
	// Read under the same lock as the snapshot: it is written from
	// sendEgressListen on another goroutine.
	egressPort := c.egressPort
	c.mu.RUnlock()

	sess := c.getSession()
	if sess == nil {
		return
	}

	// The policy goes first, before anything can be forwarded through this
	// session. The order is the same argument handleListen already makes about
	// installing routes before answering: between a sandbox being usable and a
	// sandbox being ruled, whatever the application does is unruled.
	if err := c.sendPolicy(sess); err != nil {
		log.Printf("[vtunnel-client] %v", err)
	}

	for port, addr := range fwds {
		if port == egressPort {
			continue // replayed as one egress listen below
		}
		if err := c.sendListen(sess, port, addr); err != nil {
			log.Printf("[vtunnel-client] Re-listen failed for port %d: %v", port, err)
		}
	}

	// An empty list is replayed too, once an egress proxy port exists: a fresh sandbox
	// process, or one whose routes were cleared while the tunnel was down, must
	// end up with the same allowlist this client has, which may be none.
	if len(c.proxy.Routes()) > 0 || egressPort != 0 {
		if err := c.sendEgressListen(sess); err != nil {
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
	// NewExponentialBackOff resets itself before returning, which fixes the
	// current interval at the package default of 500ms; the fields set above
	// are not read again until the next Reset. connectionLoop only resets after
	// a session that lasted, so without this the first series of retries — the
	// one that matters — ignored WithReconnectBackoff entirely.
	bo.Reset()
	return bo
}
