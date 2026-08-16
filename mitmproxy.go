package vtunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// tlsHandshakeRecordType is the first byte of a TLS handshake record (RFC 8446 §5.1).
const tlsHandshakeRecordType = 0x16

// tlsRecordHeaderLen is the number of leading bytes startsLikeTLSRecord inspects:
// content type + the two-byte legacy record version.
const tlsRecordHeaderLen = 3

// peekTimeout bounds the wait for the client's first tunnel byte, so an idle
// CONNECT can't park a goroutine and fd indefinitely.
const peekTimeout = 30 * time.Second

// dialTimeout bounds every upstream dial the proxy makes.
const dialTimeout = 10 * time.Second

// route is how one domain is served. Exactly one of three shapes:
//
//   - handler set — served in this process, no upstream connection at all
//     ([MITMProxy.Handle]).
//   - target set — TLS is terminated and the request re-issued to that address
//     ([MITMProxy.ForwardTo]). This is the only shape that can inject headers.
//   - neither — piped to the host the client asked for, TLS untouched
//     ([MITMProxy.Forward]). Needs no CA, and is the only way to reach an
//     upstream that pins certificates.
type route struct {
	handler http.Handler
	target  string
	headers http.Header
}

// terminates reports whether serving this route means decrypting the client's
// TLS, which requires a CA.
func (r route) terminates() bool { return r.handler != nil || r.target != "" }

// MITMProxy is an HTTP/CONNECT forward proxy that routes domains to in-process
// handlers, to other addresses, or straight through, and dials anything
// unrouted directly.
//
// With a MITM CA configured it terminates TLS for routes that ask for it,
// generating leaf certificates on the fly, which is what makes in-process
// handlers and header injection possible.
//
// The type owns all of its routing state and depends on neither Server nor
// Client: it works as a plain intercepting proxy on its own, and a [Client]
// mirrors its routes into a sandbox when there is a tunnel.
type MITMProxy struct {
	routes     map[string]route
	middleware []func(http.Handler) http.Handler
	unmapped   http.Handler // nil = dial the requested host directly
	onChange   func()
	domainMu   sync.RWMutex

	// mitmCA is the CA used to sign generated leaf certificates
	// (nil = transparent tunnel, no interception).
	mitmCA    *tls.Certificate
	certCache *certCache // nil until Start when no MITM CA

	transport http.Transport
	h2cProbed sync.Map // target → bool

	// tlsUpstream tracks targets that need proxy-side TLS.
	// Key: target address, Value: original hostname (for SNI).
	tlsUpstream   map[string]string
	tlsUpstreamMu sync.RWMutex

	listener net.Listener
	done     chan struct{}
	once     sync.Once
}

// MITMProxyOption configures a MITMProxy.
type MITMProxyOption func(*MITMProxy)

// WithMitmCA sets the CA certificate used for HTTPS MITM interception.
// When set, the proxy decrypts HTTPS traffic for mapped domains, generating
// certificates on the fly signed by this CA. Clients must trust it.
func WithMitmCA(cert tls.Certificate) MITMProxyOption {
	return func(p *MITMProxy) {
		p.mitmCA = &cert
	}
}

// NewMITMProxy creates a proxy with no routes.
func NewMITMProxy(opts ...MITMProxyOption) *MITMProxy {
	p := &MITMProxy{
		routes:      make(map[string]route),
		tlsUpstream: make(map[string]string),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Start begins serving on addr. It returns once the listener is open.
func (p *MITMProxy) Start(addr string) error {
	if p.mitmCA != nil {
		cc, err := newCertCache(*p.mitmCA)
		if err != nil {
			return fmt.Errorf("init MITM cert cache: %w", err)
		}
		p.certCache = cc
	}

	h2s := &http2.Server{}
	h2cHandler := h2c.NewHandler(p, h2s)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("proxy listen on %s: %w", addr, err)
	}

	p.listener = ln
	p.done = make(chan struct{})
	p.once = sync.Once{}

	log.Printf("[vtunnel-proxy] Listening on %s", addr)

	go http.Serve(ln, h2cHandler)

	return nil
}

// Addr returns the address the proxy listens on, or nil before Start.
func (p *MITMProxy) Addr() net.Addr {
	if p.listener == nil {
		return nil
	}
	return p.listener.Addr()
}

// Close stops serving. It is safe to call more than once.
func (p *MITMProxy) Close() {
	p.once.Do(func() {
		if p.done != nil {
			close(p.done)
		}
		if p.listener != nil {
			p.listener.Close()
		}
	})
}

// Handle serves a domain from this process. The proxy terminates the client's
// TLS and calls h with the decrypted request, so no upstream connection is made
// at all — which is how a service that needs custom authentication, rewriting
// or mocking is implemented without standing up a second proxy for it to reach.
//
// A handler route needs a CA: there is no way to hand a decrypted request to a
// handler without decrypting it first.
func (p *MITMProxy) Handle(domain string, h http.Handler, opts ...ForwardOption) {
	p.setRoute(domain, route{handler: h, headers: forwardHeaders(opts)},
		"handled in process")
}

// Forward routes a domain through this proxy to the host the client asked for,
// piping bytes without terminating TLS. It needs no CA and works with upstreams
// that pin certificates — but nothing can be injected into it.
func (p *MITMProxy) Forward(domain string) {
	p.setRoute(domain, route{}, "itself, TLS untouched")
}

// ForwardTo terminates the client's TLS and re-issues the request to target,
// which may be a plain address ("localhost:8080"), a TLS endpoint (":443" or an
// explicit "tls://host:port"), and carries any headers declared with
// [WithHeader].
func (p *MITMProxy) ForwardTo(domain, target string, opts ...ForwardOption) error {
	if target == "" {
		return fmt.Errorf("forward %s: empty target; use Forward to route a domain to itself", domain)
	}

	cfg := forwardConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	addr, tlsHost, upstreamIsTLS := parseForwardTarget(target)
	if cfg.sni != "" {
		tlsHost, upstreamIsTLS = cfg.sni, true
	}
	if upstreamIsTLS {
		p.setTLSUpstream(addr, tlsHost)
	}
	p.setRoute(domain, route{target: addr, headers: cfg.headers}, addr)
	return nil
}

// Remove drops a domain's route.
func (p *MITMProxy) Remove(domain string) {
	p.domainMu.Lock()
	for _, key := range domainKeys(domain) {
		delete(p.routes, key)
	}
	changed := p.onChange
	p.domainMu.Unlock()

	log.Printf("[vtunnel-proxy] Route removed: %s", domain)
	if changed != nil {
		changed()
	}
}

// Routes returns the domains this proxy serves, as "host:port" keys.
func (p *MITMProxy) Routes() []string {
	p.domainMu.RLock()
	defer p.domainMu.RUnlock()

	domains := make([]string, 0, len(p.routes))
	for domain := range p.routes {
		domains = append(domains, domain)
	}
	return domains
}

// Use adds middleware wrapping every request the proxy terminates — handler
// routes and forwarded ones alike. Middleware runs in the order given, outermost
// first, and sees the request after decryption and before header injection.
// Requests that are only piped through are never parsed, so they never reach it.
func (p *MITMProxy) Use(mw ...func(http.Handler) http.Handler) {
	p.domainMu.Lock()
	p.middleware = append(p.middleware, mw...)
	p.domainMu.Unlock()
}

// HandleUnmapped decides what happens to a request for a domain with no route.
// The default dials the requested host directly, which is what a sandbox-side
// proxy wants. A controlplane proxy usually wants to refuse instead, so that a
// compromised tunnel cannot turn it into an open relay:
//
//	proxy.HandleUnmapped(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//	    http.Error(w, "unknown domain", http.StatusForbidden)
//	}))
//
// The handler only sees requests the proxy can parse. A CONNECT for an unrouted
// host is refused outright when one is set.
func (p *MITMProxy) HandleUnmapped(h http.Handler) {
	p.domainMu.Lock()
	p.unmapped = h
	p.domainMu.Unlock()
}

// OnChange registers a callback fired after any route change. A [Client] uses
// it to mirror this proxy's domains into the sandbox as they are declared.
func (p *MITMProxy) OnChange(f func()) {
	p.domainMu.Lock()
	p.onChange = f
	p.domainMu.Unlock()
}

func (p *MITMProxy) setRoute(domain string, rt route, describe string) {
	p.domainMu.Lock()
	for _, key := range domainKeys(domain) {
		p.routes[key] = rt
	}
	changed := p.onChange
	p.domainMu.Unlock()

	log.Printf("[vtunnel-proxy] Route: %s -> %s", domain, describe)
	if changed != nil {
		changed()
	}
}

// forwardHeaders collapses ForwardOptions into the headers they declare.
func forwardHeaders(opts []ForwardOption) http.Header {
	cfg := forwardConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg.headers
}

// SetTransportTLSConfig sets the TLS settings used for upstream connections —
// extra root CAs for privately signed upstreams, or a client certificate for
// mutual TLS. Call it before Start.
func (p *MITMProxy) SetTransportTLSConfig(cfg *tls.Config) {
	p.transport.TLSClientConfig = cfg
}

// setTLSUpstream records that target needs proxy-side TLS, using host as the
// SNI name. This lets the proxy control ALPN on the upstream connection
// instead of relying on TLS being terminated further down the path.
func (p *MITMProxy) setTLSUpstream(target, host string) {
	p.tlsUpstreamMu.Lock()
	p.tlsUpstream[target] = host
	p.tlsUpstreamMu.Unlock()
}

// tlsUpstreamHost returns the original hostname for a target that needs
// proxy-side TLS (e.g. "google.com" for target "127.0.0.1:54321").
func (p *MITMProxy) tlsUpstreamHost(target string) (string, bool) {
	p.tlsUpstreamMu.RLock()
	host, ok := p.tlsUpstream[target]
	p.tlsUpstreamMu.RUnlock()
	return host, ok
}

func (p *MITMProxy) resolveDomain(host string) (route, bool) {
	p.domainMu.RLock()
	defer p.domainMu.RUnlock()

	pattern, ok := bestDomainMatch(p.routes, host)
	if !ok {
		return route{}, false
	}
	return p.routes[pattern], true
}

// unmappedHandler returns the handler for unrouted domains, or nil to dial the
// requested host directly.
func (p *MITMProxy) unmappedHandler() http.Handler {
	p.domainMu.RLock()
	defer p.domainMu.RUnlock()
	return p.unmapped
}

// wrap applies the configured middleware, outermost first.
func (p *MITMProxy) wrap(h http.Handler) http.Handler {
	p.domainMu.RLock()
	mw := p.middleware
	p.domainMu.RUnlock()

	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

func (p *MITMProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

func (p *MITMProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hostPort := r.Host
	if hostPort == "" {
		hostPort = r.URL.Host
	}

	rt, isRouted := p.resolveDomain(hostPort)

	// A routed domain may carry cleartext h2c gRPC, not only TLS.
	if isRouted && rt.terminates() && p.certCache != nil {
		p.handleConnectMITM(w, r, hostPort, rt)
		return
	}

	// Without a CA nothing can be decrypted. A target route degrades to a byte
	// pipe pointed at that target — routing still works, injection does not —
	// but a handler route has no address to fall back to.
	if isRouted && rt.handler != nil {
		log.Printf("[vtunnel-proxy] CONNECT %s: handled in process, which needs a MITM CA", hostPort)
		http.Error(w, "vtunnel: this route is served in process and requires a MITM CA", http.StatusBadGateway)
		return
	}

	if !isRouted && p.unmappedHandler() != nil {
		// A proxy that refuses unknown domains must refuse them here too:
		// letting the tunnel open first would make it an open relay.
		log.Printf("[vtunnel-proxy] CONNECT %s: no route", hostPort)
		http.Error(w, "vtunnel: no route for this domain", http.StatusForbidden)
		return
	}

	// Pipe bytes: to the route's target, to the requested host itself for a
	// Forward route, or straight out for anything unrouted.
	target := hostPort
	switch {
	case isRouted && rt.target != "":
		target = rt.target
		log.Printf("[vtunnel-proxy] CONNECT %s -> %s (TLS untouched, no CA)", hostPort, target)
	case isRouted:
		log.Printf("[vtunnel-proxy] CONNECT %s -> itself (TLS untouched)", hostPort)
	default:
		log.Printf("[vtunnel-proxy] CONNECT %s -> direct", hostPort)
	}

	targetConn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	switch r.ProtoMajor {
	case 1:
		serveHijack(w, targetConn)
	default: // HTTP/2, HTTP/3
		serveH2Connect(w, r, targetConn)
	}
}

// handleConnectMITM decides, from the client's opening bytes, how to serve a
// mapped domain: TLS goes through MITM, cleartext h2c is terminated so headers
// can still be injected, and any other cleartext is a raw byte pipe.
func (p *MITMProxy) handleConnectMITM(w http.ResponseWriter, r *http.Request, connectAuthority string, rt route) {
	rawConn := acceptConnectTunnel(w, r)
	if rawConn == nil {
		return
	}

	// Bound the wait for the opening bytes so an idle CONNECT can't park a
	// goroutine and fd; cleared once the tunnel kind is decided.
	rawConn.SetReadDeadline(time.Now().Add(peekTimeout))
	br := bufio.NewReader(rawConn)
	first, err := br.Peek(tlsRecordHeaderLen)
	if err != nil {
		rawConn.SetReadDeadline(time.Time{})
		log.Printf("[vtunnel-proxy] CONNECT %s: peek client stream failed: %v", connectAuthority, err)
		rawConn.Close()
		return
	}

	// A TLS ClientHello opens with a handshake record header; cleartext carrying
	// the HTTP/2 client preface is h2c, which we can terminate and inject into
	// just like MITM.
	isTLS := startsLikeTLSRecord(first)
	isH2C := !isTLS && isH2CPreface(br)
	rawConn.SetReadDeadline(time.Time{})
	tunnelConn := newBufferedConn(rawConn, br)

	// The h2c injection path runs a nested HTTP/2 server on the tunnel conn,
	// which is only safe on a real socket. An HTTP/2 CONNECT tunnel is backed by
	// the outer response writer, whose lifetime ends with the outer handler, so
	// a nested server's async write could fire after it and panic. Restrict
	// injection to HTTP/1.1 CONNECT (a hijacked socket); the rare h2 CONNECT
	// tunnel keeps the raw pipe.
	overHijackedSocket := r.ProtoMajor == 1

	switch {
	case isTLS:
		p.serveMITMTLS(tunnelConn, connectAuthority, rt)
	case isH2C && overHijackedSocket:
		defer tunnelConn.Close()
		log.Printf("[vtunnel-proxy] CONNECT %s: cleartext h2c, terminating", connectAuthority)
		// No pre-established upstream here: the client came in cleartext, so
		// there was no client handshake to mirror an upstream ALPN onto.
		p.serveH2(tunnelConn, rt, nil)
	case rt.handler != nil:
		// A handler route has no address to fall back to.
		defer tunnelConn.Close()
		log.Printf("[vtunnel-proxy] CONNECT %s: cleartext, but the route is served in process and this is not HTTP", connectAuthority)
	default:
		defer tunnelConn.Close()
		log.Printf("[vtunnel-proxy] CONNECT %s -> %s (cleartext, raw pipe)", connectAuthority, rt.target)
		if len(rt.headers) > 0 {
			// Raw byte pipe can't inject headers; only HTTP/1.1-CONNECT h2c is terminated.
			log.Printf("[vtunnel-proxy] WARNING: %s: %d header(s) NOT injected (raw pipe)", connectAuthority, len(rt.headers))
		}
		dialAndPipe(rt.target, tunnelConn)
	}
}

// serveMITMTLS terminates the client's TLS inside the tunnel with an on-the-fly
// cert, then proxies the decrypted h2/h1 requests to the upstream.
//
// When the upstream itself speaks TLS, the upstream handshake runs first, from
// inside GetConfigForClient, and the protocol it settles on is the only one
// offered back to the client. That mirrors gost's terminateTLS
// (x/internal/util/sniffing/sniffer_tls.go) and removes a whole class of
// mismatch: previously the client was offered {h2, http/1.1} blind, so it could
// pick h2 against an upstream that only speaks HTTP/1.1.
func (p *MITMProxy) serveMITMTLS(clientConn net.Conn, connectAuthority string, rt route) {
	log.Printf("[vtunnel-proxy] CONNECT MITM %s", connectAuthority)
	connectHost := hostFromAuthority(connectAuthority)
	target := rt.target
	sniHost, upstreamIsTLS := p.tlsUpstreamHost(target)

	base := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return p.certCache.getCert(hello, connectHost)
		},
	}

	var up *upstreamTLSConn
	cfg := base.Clone()
	if upstreamIsTLS {
		cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			u, err := p.dialTLSUpstream(hello.Context(), target, sniHost, hello.SupportedProtos)
			if err != nil {
				log.Printf("[vtunnel-proxy] MITM %s: upstream TLS to %s failed: %v", connectAuthority, target, err)
				return nil, err
			}
			up = u
			mirrored := base.Clone()
			if proto := u.proto(); proto != "" {
				mirrored.NextProtos = []string{proto}
				// A client that offered ALPN but not the protocol the upstream
				// settled on would get no_application_protocol here. This proxy
				// re-issues requests rather than piping them, so it can still
				// translate between the two; offer what the client asked for
				// and translate, instead of failing the handshake.
				if len(hello.SupportedProtos) > 0 && !slices.Contains(hello.SupportedProtos, proto) {
					log.Printf("[vtunnel-proxy] MITM %s: client ALPN %v excludes upstream %q, translating",
						connectAuthority, hello.SupportedProtos, proto)
					mirrored.NextProtos = httpALPN(hello.SupportedProtos)
				}
			}
			return mirrored, nil
		}
	} else {
		cfg.NextProtos = []string{"h2", "http/1.1"}
	}

	tlsConn := tls.Server(clientConn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[vtunnel-proxy] MITM TLS handshake failed: %v", err)
		if up != nil {
			up.close()
		}
		clientConn.Close()
		return
	}
	defer tlsConn.Close()
	// Releases the pre-established upstream only if no request ever claimed it.
	defer func() {
		if up != nil {
			up.close()
		}
	}()

	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		p.serveH2(tlsConn, rt, up)
		return
	}
	p.serveH1(tlsConn, rt, up)
}

// httpALPN narrows an ALPN offer to the protocols this proxy can actually
// proxy. Anything else would let a peer negotiate a protocol we cannot parse.
func httpALPN(offered []string) []string {
	var out []string
	for _, proto := range offered {
		if proto == "h2" || proto == "http/1.1" {
			out = append(out, proto)
		}
	}
	return out
}

// upstreamALPN is what the proxy offers the upstream on the client's behalf:
// the client's own HTTP protocols, plus HTTP/1.1 as a floor. The floor matters
// because this proxy re-issues requests rather than piping them, so an upstream
// that only speaks HTTP/1.1 still serves an h2-only client. Without it, such a
// pairing dies on the upstream handshake with no_application_protocol.
func upstreamALPN(offered []string) []string {
	out := httpALPN(offered)
	if !slices.Contains(out, "http/1.1") {
		out = append(out, "http/1.1")
	}
	return out
}

// upstreamTLSConn is a proxy-side TLS connection established during the
// client's handshake so its negotiated ALPN can be mirrored back down. The
// connection is then reused for the first request rather than thrown away.
type upstreamTLSConn struct {
	addr string
	cfg  *tls.Config
	conn *tls.Conn
	once sync.Once
}

func (u *upstreamTLSConn) proto() string {
	return u.conn.ConnectionState().NegotiatedProtocol
}

// dial hands the already-established connection to the first caller and dials
// fresh ones, with the same settings, for any caller after that. gost errors
// out instead; re-dialing keeps a dropped upstream from failing the session.
func (u *upstreamTLSConn) dial(ctx context.Context) (net.Conn, error) {
	if established := u.take(); established != nil {
		return established, nil
	}

	dialer := &net.Dialer{Timeout: dialTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", u.addr)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, u.cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// close releases the pre-established connection if no request claimed it.
func (u *upstreamTLSConn) close() {
	if established := u.take(); established != nil {
		established.Close()
	}
}

// take returns the pre-established connection exactly once.
func (u *upstreamTLSConn) take() *tls.Conn {
	var conn *tls.Conn
	u.once.Do(func() { conn = u.conn })
	return conn
}

// dialTLSUpstream opens the proxy-side TLS connection to target, offering the
// client's own ALPN list so the negotiated protocol reflects what the upstream
// really supports.
func (p *MITMProxy) dialTLSUpstream(ctx context.Context, target, sniHost string, offeredALPN []string) (*upstreamTLSConn, error) {
	cfg := &tls.Config{}
	if p.transport.TLSClientConfig != nil {
		cfg = p.transport.TLSClientConfig.Clone()
	}
	cfg.ServerName = sniHost
	cfg.NextProtos = upstreamALPN(offeredALPN)

	dialer := &net.Dialer{Timeout: dialTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return &upstreamTLSConn{addr: target, cfg: cfg, conn: conn}, nil
}

// upstreamRoundTripper builds the transport for a pre-established upstream TLS
// connection, matching whichever protocol that connection actually negotiated.
// The client may have settled on a different one — this proxy re-issues
// requests, so the two sides need not agree.
func (p *MITMProxy) upstreamRoundTripper(up *upstreamTLSConn) http.RoundTripper {
	if up.proto() == "h2" {
		return &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return up.dial(ctx)
			},
		}
	}
	transport := p.transport.Clone()
	transport.ForceAttemptHTTP2 = false
	transport.DialContext = nil
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return up.dial(ctx)
	}
	return transport
}

func (p *MITMProxy) probeH2C(target string) bool {
	if v, ok := p.h2cProbed.Load(target); ok {
		return v.(bool)
	}
	// The dial and round-trip travel the whole tunnel (server -> SSH -> client
	// -> upstream), so a transient failure — tunnel reconnecting, slow hop —
	// says nothing about whether the target speaks h2c. Cache only a
	// deterministic answer; leave transient failures unmemoized so the next
	// request re-probes instead of pinning the target to HTTP/1.1 forever.
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	// HTTP/2 connection preface
	if _, err := conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		return false
	}
	buf := make([]byte, 9) // h2 frame header
	if _, err := io.ReadFull(conn, buf); err != nil {
		return false
	}
	ok := buf[3] == 0x04 // SETTINGS frame type
	p.h2cProbed.Store(target, ok)
	return ok
}

// serveH2 serves an already-established HTTP/2 client connection — TLS-terminated
// or cleartext h2c — through the route's handler. It works on any net.Conn, so
// MITM'd TLS and raw h2c share one path.
func (p *MITMProxy) serveH2(clientConn net.Conn, rt route, up *upstreamTLSConn) {
	h2srv := &http2.Server{}
	h2srv.ServeConn(clientConn, &http2.ServeConnOpts{
		Handler: p.routeHandler(rt, up, true),
	})
}

// routeHandler turns a route into the handler that serves it: the caller's own
// handler for an in-process route, or a reverse proxy to its target. Both are
// wrapped in the configured middleware, so a Use hook sees every request the
// proxy terminates regardless of where it ends up.
func (p *MITMProxy) routeHandler(rt route, up *upstreamTLSConn, preferH2 bool) http.Handler {
	var h http.Handler
	if rt.handler != nil {
		h = rt.handler
	} else {
		h = p.forwardingHandler(rt.target, up, preferH2)
	}

	inject := rt.headers
	return p.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RequestURI = ""
		removeHopByHop(r.Header, preferH2)
		injectConfiguredHeaders(r.Header, inject)
		h.ServeHTTP(w, r)
	}))
}

// forwardingHandler re-issues a decrypted request to target.
func (p *MITMProxy) forwardingHandler(target string, up *upstreamTLSConn, preferH2 bool) http.Handler {
	transport, scheme := p.upstreamTransport(target, up, preferH2)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Scheme = scheme
		r.URL.Host = target

		resp, err := transport.RoundTrip(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// Trailer names have to be announced before the body when the client
		// speaks HTTP/2.
		for k := range resp.Trailer {
			w.Header().Add("Trailer", k)
		}
		copyResponse(w, resp)
	})
}

// upstreamTransport picks how to reach target and which scheme that implies.
func (p *MITMProxy) upstreamTransport(target string, up *upstreamTLSConn, preferH2 bool) (http.RoundTripper, string) {
	if up != nil {
		// Upstream TLS is already up and negotiated; reuse it instead of
		// handshaking a second time.
		return p.upstreamRoundTripper(up), "https"
	}

	if tlsHost, ok := p.tlsUpstreamHost(target); ok {
		// Proxy-side TLS: dial the target, then handshake using the real
		// server's hostname for SNI.
		dialer := &net.Dialer{Timeout: dialTimeout}
		transport := p.transport.Clone()
		transport.ForceAttemptHTTP2 = preferH2
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, target)
		}
		transport.DialTLSContext = nil

		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		} else {
			transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		}
		transport.TLSClientConfig.ServerName = tlsHost
		if preferH2 {
			transport.TLSClientConfig.NextProtos = []string{"h2", "http/1.1"}
		} else {
			transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
		}
		return transport, "https"
	}

	if preferH2 && p.probeH2C(target) {
		return &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return net.DialTimeout(network, addr, dialTimeout)
			},
		}, "http"
	}

	return &p.transport, "http"
}

// serveH1 serves a decrypted HTTP/1.1 connection through net/http, which brings
// keep-alive, chunking and trailer handling with it, and lets a handler route
// and a forwarded one run through exactly the same code.
func (p *MITMProxy) serveH1(clientConn net.Conn, rt route, up *upstreamTLSConn) {
	ln := newOneShotListener(clientConn)
	srv := &http.Server{Handler: p.routeHandler(rt, up, false)}
	_ = srv.Serve(ln)
}

// oneShotListener hands one already-established connection to net/http. The
// second Accept blocks until that connection is done, so Serve does not return
// while the connection is still being used.
type oneShotListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func newOneShotListener(conn net.Conn) *oneShotListener {
	return &oneShotListener{conn: conn, done: make(chan struct{})}
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	var first net.Conn
	l.once.Do(func() {
		first = &notifyConn{Conn: l.conn, done: l.done}
	})
	if first != nil {
		return first, nil
	}
	<-l.done
	return nil, io.EOF
}

func (l *oneShotListener) Close() error { return nil }

func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

// notifyConn signals when net/http is finished with the connection.
type notifyConn struct {
	net.Conn
	once sync.Once
	done chan struct{}
}

func (c *notifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}

func (p *MITMProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	hostPort := r.Host
	if _, _, err := net.SplitHostPort(hostPort); err != nil {
		port := "80"
		if r.URL.Scheme == "https" {
			port = "443"
		}
		hostPort = net.JoinHostPort(hostPort, port)
	}

	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	r.Proto = "HTTP/1.1"
	r.ProtoMajor = 1
	r.ProtoMinor = 1

	rt, isRouted := p.resolveDomain(hostPort)
	switch {
	case !isRouted:
		if unmapped := p.unmappedHandler(); unmapped != nil {
			log.Printf("[vtunnel-proxy] %s %s: no route", r.Method, hostPort)
			p.wrap(unmapped).ServeHTTP(w, r)
			return
		}
		// Nothing routed and nothing to refuse with: send it where it asked to go.
		rt = route{target: hostPort}
	case rt.target == "" && rt.handler == nil:
		// A Forward route is a pipe for TLS; in the clear there is nothing to
		// pipe, so it behaves as "go to the host you asked for".
		rt.target = hostPort
	}

	if rt.handler == nil {
		log.Printf("[vtunnel-proxy] %s %s %s -> %s", r.URL.Scheme, r.Method, hostPort, rt.target)
	} else {
		log.Printf("[vtunnel-proxy] %s %s %s -> handled in process", r.URL.Scheme, r.Method, hostPort)
	}
	p.routeHandler(rt, nil, false).ServeHTTP(w, r)
}

// acceptConnectTunnel sends the CONNECT success response and returns a net.Conn
// to the client — HTTP/1.x (hijack) or HTTP/2 (RFC 8441 extended CONNECT). It
// owns the whole response and returns nil on failure (logging the cause): once
// 200 is committed or the conn is hijacked, w can no longer carry an error
// status, so the caller must not write to w after a nil.
func acceptConnectTunnel(w http.ResponseWriter, r *http.Request) net.Conn {
	if r.ProtoMajor != 1 {
		w.WriteHeader(http.StatusOK)
		if err := http.NewResponseController(w).Flush(); err != nil {
			log.Printf("[vtunnel-proxy] CONNECT %s: flush h2 200 failed: %v", r.Host, err)
			return nil
		}
		return newH2StreamConn(r.Body, w)
	}

	clientConn, brw, err := hijack(w)
	if err != nil {
		log.Printf("[vtunnel-proxy] CONNECT %s: hijack failed: %v", r.Host, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}
	if _, err := brw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		log.Printf("[vtunnel-proxy] CONNECT %s: write 200 failed: %v", r.Host, err)
		clientConn.Close()
		return nil
	}
	if err := brw.Flush(); err != nil {
		log.Printf("[vtunnel-proxy] CONNECT %s: flush 200 failed: %v", r.Host, err)
		clientConn.Close()
		return nil
	}
	// net/http may have already buffered tunneled bytes after CONNECT headers.
	// Keep reading through that buffer so handshake/preface bytes aren't dropped.
	return newBufferedConn(clientConn, brw.Reader)
}

// dialAndPipe lets cleartext traffic on a MITM-configured domain still reach
// its upstream, reusing the no-MITM raw byte pipe.
func dialAndPipe(target string, clientConn net.Conn) {
	targetConn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		log.Printf("[vtunnel-proxy] dial %s failed: %v", target, err)
		return
	}
	defer targetConn.Close()
	dualStream(targetConn, clientConn, clientConn)
}

// startsLikeTLSRecord reports whether the bytes look like the start of a TLS
// handshake record: a handshake content type (0x16) followed by a legacy record
// version of 0x03 0x00-0x03 (SSLv3 through TLS 1.3, which pins the record
// version at 0x0303). Checking the version too, not just the content type,
// keeps a cleartext protocol that happens to open with 0x16 out of the TLS
// path. Mirrors mitmproxy's starts_like_tls_record.
func startsLikeTLSRecord(d []byte) bool {
	return len(d) >= tlsRecordHeaderLen &&
		d[0] == tlsHandshakeRecordType &&
		d[1] == 0x03 && d[2] <= 0x03
}

// isH2CPreface reports whether the buffered stream opens with the HTTP/2 client
// connection preface (RFC 7540 §3.5) — the marker of cleartext h2c, which sends
// it over CONNECT in place of a TLS ClientHello.
func isH2CPreface(br *bufio.Reader) bool {
	p, err := br.Peek(len(http2.ClientPreface))
	if err != nil {
		return false
	}
	return string(p) == http2.ClientPreface
}

func hostFromAuthority(authority string) string {
	if authority == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(authority)
	if err == nil {
		return host
	}
	return strings.Trim(authority, "[]")
}
