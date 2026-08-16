package vtunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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

// mitmHandshakeTimeout bounds the client's TLS handshake once the peek deadline
// has been cleared. Without it a client that sends a record header and then
// stops holds a goroutine and a file descriptor for the life of the process:
// peekTimeout only ever covered the wait for the first byte.
//
// A variable rather than a constant so tests need not wait it out.
var mitmHandshakeTimeout = 30 * time.Second

// noMITMTTL is how long a domain stays out of interception after refusing it.
// Long enough not to retry a doomed handshake on every request, short enough
// that fixing the cause — installing the CA in the client, giving the proxy a
// client certificate — takes effect without a restart.
const noMITMTTL = 10 * time.Minute

// maxNoMITMEntries bounds the learned exclusions, which are keyed by whatever
// authority a client asked for and so must not grow unboundedly.
const maxNoMITMEntries = 1024

// serverReadHeaderTimeout bounds a peer that opens a connection and then does
// not finish sending a request. Go's default is no limit at all, so one byte of
// a request line pinned a goroutine and a file descriptor for the life of the
// process — the same hazard peekTimeout, mitmHandshakeTimeout and
// connectReplyTimeout exist to close one layer further in.
//
// It is the only timeout the servers get, and deliberately so. A proxy has no
// business deciding when a connection between two healthy endpoints is stale:
//
//   - IdleTimeout only ever bites a well-behaved keep-alive connection between
//     requests — net/http arms it exactly there, and arms ReadHeaderTimeout
//     only once the first bytes of the next request have arrived
//     (net/http/server.go, "Wait for the connection to become readable again").
//     So it defends against nothing that ReadHeaderTimeout does not already
//     cover, and costs a GOAWAY on every quiet gRPC channel and a dropped
//     connection on every idle pool.
//   - ReadTimeout and WriteTimeout would cut off a legitimate slow body, a
//     streaming response, or an upstream that simply took five minutes to
//     answer. Those are the endpoints' business, not this hop's.
const serverReadHeaderTimeout = 30 * time.Second

// idleConnTimeout is how long an unused upstream connection is kept in the
// pool. The zero value net/http defaults to means "forever", which on a pooled
// transport is a connection and two goroutines that never come back.
//
// Unlike a server-side idle timeout this is the proxy's own resource, not
// somebody's live connection: the pool exists to be reaped, and nothing is
// interrupted by dropping an entry from it. It is the same 90 seconds
// http.DefaultTransport uses.
const idleConnTimeout = 90 * time.Second

// errClientCertRequested marks a handshake the upstream asked to authenticate
// with a client certificate. It wraps the underlying failure rather than
// replacing it, so the original cause stays readable in logs.
var errClientCertRequested = errors.New("upstream requested a client certificate")

// errNoMitmCA is returned when a route is declared that could only be served by
// decrypting, on a proxy that holds no CA.
//
// Refusing at declaration rather than at request time is the whole point.
// Injection happens after TLS is terminated, so on a proxy that cannot
// terminate it, a route configured with headers answers requests perfectly
// normally and simply never adds the credential — a failure with no error and
// no missing response to notice. The CLI has always rejected `-H` without
// `-mitm-ca`; this is the same rule for callers of the library.
var errNoMitmCA = errors.New("no MITM CA is configured: pass WithMitmCA, or WithMitm on a Client")

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
	// tlsHost is the server name to present when opening TLS to target, empty
	// when the target is reached in the clear.
	//
	// It lives on the route rather than in a map keyed by address because two
	// routes may share an address and disagree about it — one tls://, one not —
	// and a map could then hand the wrong answer to whichever asked second, or
	// keep a stale mark alive after the route that set it was replaced.
	tlsHost string
}

// terminates reports whether serving this route means decrypting the client's
// TLS, which requires a CA.
func (r route) terminates() bool { return r.handler != nil || r.target != "" }

// canFallBack reports whether this route may quietly degrade to a byte pipe when
// interception turns out to be impossible. It needs somewhere to pipe to, and it
// must not be carrying headers — a route that stopped injecting a credential but
// kept working would hide the failure instead of surfacing it.
func (r route) canFallBack() bool { return r.target != "" && len(r.headers) == 0 }

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
	mitmCA        *tls.Certificate
	certCacheOnce sync.Once
	certCacheVal  *certCache
	certCacheErr  error

	transport http.Transport
	h2cProbed sync.Map // target → bool

	// upstreams holds one transport per distinct upstream. Building one per
	// request looked harmless and leaked: a clone of a zero-value
	// http.Transport inherits IdleConnTimeout 0, so net/http never arms its
	// idle reaper, and the clone goes out of scope after RoundTrip with nobody
	// left to call CloseIdleConnections — an idle connection plus its read and
	// write goroutines then live until the process exits. Keep-alive never
	// worked either, since every request opened a fresh connection. Router
	// already fixed this for its own chained transports; this is the same fix.
	upstreams   map[upstreamKey]http.RoundTripper
	upstreamsMu sync.Mutex

	// lifecycleMu guards everything Start initialises. Addr, Close, Shutdown
	// and closed all read these from other goroutines, so writing them bare was
	// a race the detector catches.
	lifecycleMu sync.Mutex
	listener    net.Listener
	srv         *http.Server
	stopped     bool

	// detached holds the connections the outer http.Server no longer manages:
	// an HTTP/1.1 CONNECT is hijacked, and net/http stops tracking a connection
	// the moment it is, while an HTTP/2 CONNECT lives as a stream wrapped in a
	// net.Conn. Either way Close cannot reach them through the server — and the
	// nested servers that carry decrypted traffic ([MITMProxy.serveH1],
	// [MITMProxy.serveH2]) sit on exactly these. Closing the connection is what
	// unwinds them.
	//
	// Nothing here relates to the SSH tunnel between [Server] and [Client]:
	// MITMProxy has no knowledge of either.
	detached   map[io.Closer]struct{}
	detachedMu sync.Mutex
	detachedWg sync.WaitGroup

	// nested holds the http.Servers running on detached connections. They are
	// the only place the proxy knows where a request ends, so they are what lets
	// Shutdown stop at a boundary rather than mid-response.
	nested   map[*http.Server]struct{}
	nestedMu sync.Mutex

	// noMITM excludes domains from interception: value is when the exclusion
	// lapses, zero for the ones configured through [MITMProxy.MITMExceptions].
	// Entries are learned from handshakes that could not have succeeded —
	// a pinned client, an upstream wanting mutual TLS.
	noMITM   map[string]time.Time
	noMITMMu sync.RWMutex
}

// MITMProxyOption configures a MITMProxy.
type MITMProxyOption func(*MITMProxy)

// WithMitmCA sets the CA certificate used for HTTPS MITM interception.
// When set, the proxy decrypts HTTPS traffic for mapped domains, generating
// certificates on the fly signed by this CA. Clients must trust it.
//
// For debugging, setting $SSLKEYLOGFILE makes the proxy append the session keys
// of both legs — client and upstream — to that file, so an intercepted session
// can be read in Wireshark. It renders that traffic readable to anyone holding
// the file, so leave it unset outside development.
func WithMitmCA(cert tls.Certificate) MITMProxyOption {
	return func(p *MITMProxy) {
		p.mitmCA = &cert
	}
}

// NewMITMProxy creates a proxy with no routes.
func NewMITMProxy(opts ...MITMProxyOption) *MITMProxy {
	p := &MITMProxy{
		routes: make(map[string]route),
		// Built here rather than in Start: it is guarded by its own mutex, and
		// initialising it there raced with a concurrent Close reading it.
		detached: make(map[io.Closer]struct{}),
	}
	// The cleartext path is the only one that used the base transport as it
	// came, and a zero http.Transport dials with no timeout at all and keeps
	// idle connections forever, while every other dial the proxy makes is
	// bounded by dialTimeout.
	p.transport.DialContext = (&net.Dialer{Timeout: dialTimeout}).DialContext
	p.transport.IdleConnTimeout = idleConnTimeout
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// certs returns the leaf-certificate cache, building it on first use, or nil
// when the proxy holds no CA.
//
// It is built here rather than in Start because interception must not depend on
// how the proxy is being served. ServeHTTP is exported and handing the proxy to
// http.Serve is a documented shape; gating interception on state only Start
// installed made such a proxy answer every request perfectly normally while
// silently injecting nothing — the exact failure errNoMitmCA exists to make
// impossible at declaration time.
func (p *MITMProxy) certs() (*certCache, error) {
	if p.mitmCA == nil {
		return nil, nil
	}
	p.certCacheOnce.Do(func() {
		p.certCacheVal, p.certCacheErr = newCertCache(*p.mitmCA)
	})
	return p.certCacheVal, p.certCacheErr
}

// Start begins serving on addr. It returns once the listener is open.
//
// A proxy serves one address: starting a second time is refused rather than
// silently replacing the listener and orphaning the first, and starting one
// that has been closed is refused too.
func (p *MITMProxy) Start(addr string) error {
	if _, err := p.certs(); err != nil {
		return fmt.Errorf("init MITM cert cache: %w", err)
	}

	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()

	if p.stopped {
		return errors.New("proxy is closed")
	}
	if p.listener != nil {
		return fmt.Errorf("proxy is already listening on %s", p.listener.Addr())
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("proxy listen on %s: %w", addr, err)
	}

	h2s := &http2.Server{}
	srv := &http.Server{
		Handler:           h2c.NewHandler(p, h2s),
		ReadHeaderTimeout: serverReadHeaderTimeout,
	}

	p.listener = ln
	p.srv = srv

	log.Printf("[vtunnel-proxy] Listening on %s", addr)

	go srv.Serve(ln)

	return nil
}

// lifecycle returns the state Start installed, as one consistent snapshot.
func (p *MITMProxy) lifecycle() (net.Listener, *http.Server) {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	return p.listener, p.srv
}

// Addr returns the address the proxy listens on, or nil before Start.
func (p *MITMProxy) Addr() net.Addr {
	ln, _ := p.lifecycle()
	if ln == nil {
		return nil
	}
	return ln.Addr()
}

// Close stops serving immediately: the listener goes down and every connection
// still open is dropped, including the CONNECT connections and the nested servers
// running on top of them. Requests in flight are cut off. It is safe to call
// more than once, and safe before Start.
//
// Use [MITMProxy.Shutdown] to let in-flight requests finish first.
func (p *MITMProxy) Close() {
	p.stopAccepting()
	ln, srv := p.lifecycle()
	if srv != nil {
		srv.Close()
	} else if ln != nil {
		ln.Close()
	}
	p.closeDetached()
	p.closeIdleUpstreams()
}

// Shutdown stops accepting new connections and lets the requests already in
// flight finish before dropping what is left. It returns nil when everything
// drained in time and ctx's error when the deadline arrived first.
//
// A raw byte pipe has no request boundary to wait for and an idle CONNECT
// tunnel is indistinguishable from a busy one, so those are only ever ended by
// the deadline. Give ctx a bound you are willing to wait; for an immediate stop
// use [MITMProxy.Close].
func (p *MITMProxy) Shutdown(ctx context.Context) error {
	p.stopAccepting()

	// The nested servers are stopped concurrently with the outer one, not after
	// it. An HTTP/2 CONNECT is still an in-flight request as far as the outer
	// server is concerned, so waiting on that first would have it block on the
	// very tunnel whose nested server is waiting to be told to stop.
	nestedDone := make(chan struct{})
	go func() {
		defer close(nestedDone)
		p.shutdownNested(ctx)
	}()

	ln, srv := p.lifecycle()
	var err error
	if srv != nil {
		err = srv.Shutdown(ctx)
	} else if ln != nil {
		ln.Close()
	}
	<-nestedDone

	// http.Server.Shutdown knows nothing about hijacked connections — the whole
	// point of hijacking is that the server hands ownership over — so the
	// detached ones are waited on separately.
	drained := make(chan struct{})
	go func() {
		p.detachedWg.Wait()
		close(drained)
	}()

	select {
	case <-drained:
	case <-ctx.Done():
		if err == nil {
			err = ctx.Err()
		}
	}

	p.closeDetached()
	p.closeIdleUpstreams()
	return err
}

// closeIdleUpstreams drops the idle connections every upstream transport is
// holding, the base one included.
func (p *MITMProxy) closeIdleUpstreams() {
	p.transport.CloseIdleConnections()

	p.upstreamsMu.Lock()
	transports := make([]http.RoundTripper, 0, len(p.upstreams))
	for _, t := range p.upstreams {
		transports = append(transports, t)
	}
	p.upstreamsMu.Unlock()

	for _, t := range transports {
		if idler, ok := t.(interface{ CloseIdleConnections() }); ok {
			idler.CloseIdleConnections()
		}
	}
}

// trackNested registers a server running on a detached connection, returning the
// function that unregisters it.
func (p *MITMProxy) trackNested(srv *http.Server) func() {
	p.nestedMu.Lock()
	if p.nested == nil {
		p.nested = make(map[*http.Server]struct{})
	}
	p.nested[srv] = struct{}{}
	p.nestedMu.Unlock()

	return func() {
		p.nestedMu.Lock()
		delete(p.nested, srv)
		p.nestedMu.Unlock()
	}
}

// shutdownNested asks every server on a detached connection to stop once its
// current request is done. Each one owns a single connection, so this is what
// turns "wait for in-flight requests" into something the proxy can actually do.
func (p *MITMProxy) shutdownNested(ctx context.Context) {
	p.nestedMu.Lock()
	servers := make([]*http.Server, 0, len(p.nested))
	for srv := range p.nested {
		servers = append(servers, srv)
	}
	p.nestedMu.Unlock()

	var wg sync.WaitGroup
	for _, srv := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = srv.Shutdown(ctx)
		}()
	}
	wg.Wait()
}

// stopAccepting marks the proxy as shutting down, which is what makes closed()
// report true. It is safe before Start and safe to repeat.
//
// A plain flag rather than a sync.Once over a channel: Close is documented safe
// before Start, and doing that used to spend the once on a no-op, so the guard
// never armed for the proxy that was started afterwards.
func (p *MITMProxy) stopAccepting() {
	p.lifecycleMu.Lock()
	p.stopped = true
	p.lifecycleMu.Unlock()
}

// closed reports whether the proxy is shutting down.
func (p *MITMProxy) closed() bool {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	return p.stopped
}

// track registers a connection so Close can reach it and Shutdown can wait for
// it, returning the function that undoes both. The caller must defer it.
func (p *MITMProxy) track(c io.Closer) func() {
	p.detachedWg.Add(1)

	p.detachedMu.Lock()
	if p.detached == nil {
		p.detached = make(map[io.Closer]struct{})
	}
	p.detached[c] = struct{}{}
	p.detachedMu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			p.detachedMu.Lock()
			delete(p.detached, c)
			p.detachedMu.Unlock()
			p.detachedWg.Done()
		})
	}
}

// closeDetached drops every tracked connection. The map is emptied first so a
// concurrent Close does not double-close, and so the untrack functions still
// running have nothing left to find.
func (p *MITMProxy) closeDetached() {
	p.detachedMu.Lock()
	conns := make([]io.Closer, 0, len(p.detached))
	for c := range p.detached {
		conns = append(conns, c)
	}
	clear(p.detached)
	p.detachedMu.Unlock()

	for _, c := range conns {
		c.Close()
	}
}

// Handle serves a domain from this process. The proxy terminates the client's
// TLS and calls h with the decrypted request, so no upstream connection is made
// at all — which is how a service that needs custom authentication, rewriting
// or mocking is implemented without standing up a second proxy for it to reach.
//
// A handler route needs a CA and is refused without one: there is no way to
// hand a decrypted request to a handler without decrypting it first, and a
// route that could only ever answer HTTPS with an error is better reported when
// it is declared than on every request that reaches it.
func (p *MITMProxy) Handle(domain string, h http.Handler, opts ...ForwardOption) error {
	if p.mitmCA == nil {
		return fmt.Errorf("handle %s: serving a domain in process means decrypting it, %w",
			domain, errNoMitmCA)
	}
	p.setRoute(domain, route{handler: h, headers: forwardHeaders(opts)},
		"handled in process")
	return nil
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

	if len(cfg.headers) > 0 && p.mitmCA == nil {
		return fmt.Errorf("forward %s: %d configured header(s) need a MITM CA, %w",
			domain, len(cfg.headers), errNoMitmCA)
	}

	addr, tlsHost, upstreamIsTLS := parseForwardTarget(target)
	if cfg.sni != "" {
		tlsHost, upstreamIsTLS = cfg.sni, true
	}
	if !upstreamIsTLS {
		tlsHost = ""
	}
	p.setRoute(domain, route{target: addr, headers: cfg.headers, tlsHost: tlsHost}, addr)
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
//
// Middleware that substitutes its own [http.ResponseWriter] takes on two
// obligations, and a wrapper is the natural place to inspect or rewrite what
// passes through:
//
//   - Implement Unwrap() http.ResponseWriter. Streaming responses stay
//     incremental only because the proxy flushes after every write, and
//     [http.ResponseController] finds the flusher by unwrapping. Without it a
//     server-sent event stream stops at its first event.
//   - Forward [http.Hijacker], or implement Hijack over the original. Completing
//     a protocol upgrade means taking the connection over, and a wrapper that
//     cannot be hijacked has no connection to hand across. Note that the proxy
//     reads through the *bufio.ReadWriter that Hijack returns, so a wrapper
//     meaning to observe an upgraded connection must wrap that too — replacing
//     only the net.Conn leaves one direction of the traffic unseen.
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

	// Replacing a route can orphan a TLS mark too: the same domain pointed at a
	// tls:// target a moment ago and at a cleartext one now.

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
//
// Transports already built from the previous settings are dropped, so calling
// it late still takes effect on the next request rather than leaving pooled
// connections dialled under the old configuration.
func (p *MITMProxy) SetTransportTLSConfig(cfg *tls.Config) {
	p.transport.TLSClientConfig = cfg

	p.upstreamsMu.Lock()
	stale := make([]http.RoundTripper, 0, len(p.upstreams))
	for _, transport := range p.upstreams {
		stale = append(stale, transport)
	}
	clear(p.upstreams)
	p.upstreamsMu.Unlock()

	for _, transport := range stale {
		if idler, ok := transport.(interface{ CloseIdleConnections() }); ok {
			idler.CloseIdleConnections()
		}
	}
}

// MITMExceptions marks domains that must never be intercepted, whatever their
// route says. Use it for upstreams known to pin certificates or to require a
// client certificate the proxy does not hold: their traffic is piped through
// untouched instead of failing a handshake on every request.
//
// The proxy also learns this on its own — see [MITMProxy.ForwardTo] — so this is
// for cases worth stating up front rather than discovering. Entries added here
// never expire.
func (p *MITMProxy) MITMExceptions(domains ...string) {
	p.noMITMMu.Lock()
	if p.noMITM == nil {
		p.noMITM = make(map[string]time.Time)
	}
	for _, domain := range domains {
		for _, key := range domainKeys(domain) {
			p.noMITM[key] = time.Time{} // zero: no expiry
		}
	}
	p.noMITMMu.Unlock()

	log.Printf("[vtunnel-proxy] MITM exceptions: %v", domains)
}

// mitmBlocked reports whether interception is currently off for this authority,
// dropping the entry if its exclusion has run out. configured tells the two
// kinds apart: an entry the caller declared through [MITMProxy.MITMExceptions],
// as against one the proxy learned from a handshake that could not work.
//
// The lookup goes through bestDomainMatch, the same resolver routes use, so a
// wildcard exception covers what the same wildcard route would. An exact map
// lookup meant MITMExceptions("*.pinned.corp") matched nothing at all and
// silently did nothing.
func (p *MITMProxy) mitmBlocked(authority string) (blocked, configured bool) {
	p.noMITMMu.RLock()
	key, ok := bestDomainMatch(p.noMITM, authority)
	var expiry time.Time
	if ok {
		expiry = p.noMITM[key]
	}
	p.noMITMMu.RUnlock()

	switch {
	case !ok:
		return false, false
	case expiry.IsZero(): // configured by hand, permanent
		return true, true
	case time.Now().Before(expiry):
		return true, false
	}

	p.noMITMMu.Lock()
	if current, still := p.noMITM[key]; still && current.Equal(expiry) {
		delete(p.noMITM, key)
	}
	p.noMITMMu.Unlock()
	return false, false
}

// noteMITMFailure decides what a failed interception means for the next request
// to the same domain.
//
// Only a route that can degrade is ever excluded. A route carrying injected
// headers is deliberately left to keep failing: quietly dropping to a pipe would
// keep the request working while the credential it depends on stopped being
// added, which is a worse outcome than an error. A handler route has no address
// to pipe to at all.
func (p *MITMProxy) noteMITMFailure(authority string, rt route, err error) {
	if !mitmRefused(err) {
		return
	}

	if !rt.canFallBack() {
		if len(rt.headers) > 0 {
			log.Printf("[vtunnel-proxy] MITM %s refused (%v); still intercepting, because %d configured header(s) would otherwise stop being injected without saying so",
				authority, err, len(rt.headers))
		}
		return
	}

	p.noMITMMu.Lock()
	if p.noMITM == nil {
		p.noMITM = make(map[string]time.Time)
	}
	if len(p.noMITM) >= maxNoMITMEntries {
		p.sweepNoMITMLocked(time.Now())
	}
	p.noMITM[strings.ToLower(authority)] = time.Now().Add(noMITMTTL)
	p.noMITMMu.Unlock()

	log.Printf("[vtunnel-proxy] WARNING: MITM %s refused (%v); piping to %s untouched for the next %v, so nothing is injected into it",
		authority, err, rt.target, noMITMTTL)
}

// sweepNoMITMLocked drops expired exclusions. Permanent ones stay: they were
// configured, not learned.
//
// When nothing has expired yet the map would otherwise keep growing past its
// bound, so learned entries are evicted until there is room — map order is
// random, which is as fair a victim as any here. Re-learning a dropped entry
// costs one failed handshake; keeping every authority a client ever asked for
// costs memory that never comes back.
func (p *MITMProxy) sweepNoMITMLocked(now time.Time) {
	for authority, expiry := range p.noMITM {
		if !expiry.IsZero() && !now.Before(expiry) {
			delete(p.noMITM, authority)
		}
	}
	for authority, expiry := range p.noMITM {
		if len(p.noMITM) < maxNoMITMEntries {
			return
		}
		if expiry.IsZero() {
			continue // configured, not ours to drop
		}
		delete(p.noMITM, authority)
	}
}

// mitmRefused reports whether err means interception cannot work for this
// domain, as opposed to a transient failure that is worth retrying. Getting this
// wrong in the permissive direction turns a blip into minutes of un-intercepted
// traffic, so only causes that are properties of the peer count.
func mitmRefused(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errClientCertRequested) {
		return true
	}

	// The upstream's own certificate did not check out. Piping lets the client
	// make that judgement itself, which it is better placed to do than we are.
	var unknownAuthority x509.UnknownAuthorityError
	var invalidCert x509.CertificateInvalidError
	var wrongHost x509.HostnameError
	if errors.As(err, &unknownAuthority) || errors.As(err, &invalidCert) || errors.As(err, &wrongHost) {
		return true
	}

	// The client rejecting our generated leaf arrives as a TLS alert rather than
	// a typed error — this is what certificate pinning looks like from here.
	// Every alert that means "your certificate is the problem" renders with the
	// word certificate in it: bad certificate, unknown certificate authority,
	// certificate expired, certificate required. Alerts that do not — handshake
	// failure, protocol version — are deliberately left out: those can also come
	// from a cipher or version mismatch, and treating one as pinning would turn
	// a blip into ten minutes of un-intercepted traffic.
	msg := err.Error()
	return strings.Contains(msg, "remote error: tls:") && strings.Contains(msg, "certificate")
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

	// A CONNECT taken over now would outlive the shutdown: once detached it is no
	// longer the server's to close, so refuse before that happens.
	if p.closed() {
		log.Printf("[vtunnel-proxy] CONNECT %s: refused, proxy is shutting down", hostPort)
		http.Error(w, "vtunnel: proxy is shutting down", http.StatusServiceUnavailable)
		return
	}

	rt, isRouted := p.resolveDomain(hostPort)

	certs, err := p.certs()
	if err != nil {
		log.Printf("[vtunnel-proxy] CONNECT %s: MITM cert cache unusable: %v", hostPort, err)
	}

	// A routed domain may carry cleartext h2c gRPC, not only TLS.
	intercept := isRouted && rt.terminates() && certs != nil
	if intercept {
		switch blocked, configured := p.mitmBlocked(hostPort); {
		case !blocked:
		case rt.target == "":
			// A handler route has no address to pipe to, so the exclusion cannot
			// be honoured however it was arrived at.
			log.Printf("[vtunnel-proxy] CONNECT %s: excluded from interception, but the route is served in process and there is nowhere to pipe to; still intercepting", hostPort)
		case configured:
			// Named by the caller, so it outranks the header rule below: they
			// asked for this domain to be left alone knowing what it carries.
			if len(rt.headers) > 0 {
				log.Printf("[vtunnel-proxy] WARNING: CONNECT %s: configured MITM exception, so %d header(s) will NOT be injected", hostPort, len(rt.headers))
			}
			log.Printf("[vtunnel-proxy] CONNECT %s: configured MITM exception, piping to %s", hostPort, rt.target)
			intercept = false
		case rt.canFallBack():
			log.Printf("[vtunnel-proxy] CONNECT %s: interception is off for this domain, piping to %s", hostPort, rt.target)
			intercept = false
		}
	}
	if intercept {
		p.handleConnectMITM(w, r, hostPort, rt, certs)
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
		// The cause is logged here and not sent back: the reply crosses the
		// tunnel, and a dial error names the controlplane-internal address it
		// just tried, which is precisely what never leaves this side.
		log.Printf("[vtunnel-proxy] CONNECT %s -> %s failed: %v", hostPort, target, err)
		http.Error(w, "vtunnel: upstream connection failed", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()
	defer p.track(targetConn)()

	// acceptConnectTunnel rather than serveHijack: it answers both HTTP/1.1 and
	// HTTP/2 CONNECT the same way and hands back the connection, which is what
	// lets the client side be tracked too. Closing only the upstream would not
	// unblock a pipe waiting on a silent client.
	clientConn := acceptConnectTunnel(w, r)
	if clientConn == nil {
		return
	}
	defer clientConn.Close()
	defer p.track(clientConn)()

	dualStream(targetConn, clientConn, clientConn)
}

// handleConnectMITM decides, from the client's opening bytes, how to serve a
// mapped domain: TLS goes through MITM, cleartext h2c is terminated so headers
// can still be injected, and any other cleartext is a raw byte pipe.
func (p *MITMProxy) handleConnectMITM(w http.ResponseWriter, r *http.Request, connectAuthority string, rt route, certs *certCache) {
	rawConn := acceptConnectTunnel(w, r)
	if rawConn == nil {
		return
	}
	// Everything below — the peek, the MITM handshake, the nested h1/h2 server
	// serving the decrypted stream — hangs off this one connection, so tracking
	// it is enough for Close to unwind the whole tunnel.
	defer p.track(rawConn)()

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
		p.serveMITMTLS(tunnelConn, connectAuthority, rt, certs)
	case isH2C && overHijackedSocket:
		defer tunnelConn.Close()
		log.Printf("[vtunnel-proxy] CONNECT %s: cleartext h2c, terminating", connectAuthority)
		// No pre-established upstream here: the client came in cleartext, so
		// there was no client handshake to mirror an upstream ALPN onto.
		p.serveH2(tunnelConn, connectAuthority, rt, nil)
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
		p.dialAndPipe(rt.target, tunnelConn)
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
func (p *MITMProxy) serveMITMTLS(clientConn net.Conn, connectAuthority string, rt route, certs *certCache) {
	log.Printf("[vtunnel-proxy] CONNECT MITM %s", connectAuthority)
	connectHost := hostFromAuthority(connectAuthority)
	target := rt.target
	sniHost, upstreamIsTLS := rt.tlsHost, rt.tlsHost != ""

	base := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return certs.getCert(hello, connectHost)
		},
		// Both clones below inherit this, so the client half of every
		// intercepted session is covered by one assignment.
		KeyLogWriter: tlsKeyLogWriter(),
		// The floor the mirroring below starts from. An upstream that negotiates
		// no ALPN at all leaves nothing to mirror, and without this the proxy
		// would answer ServerHello with no ALPN extension — which a client that
		// requires one, gRPC among them, cannot use.
		NextProtos: []string{"h2", "http/1.1"},
	}

	var up *upstreamTLSConn
	cfg := base.Clone()
	if upstreamIsTLS {
		cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			u, err := p.dialTLSUpstream(hello.Context(), target, sniHost, hello.SupportedProtos)
			if err != nil {
				log.Printf("[vtunnel-proxy] MITM %s: upstream TLS to %s failed: %v", connectAuthority, target, err)
				// Noted here rather than only at the handshake below: the client
				// error this turns into says nothing about the upstream cause.
				p.noteMITMFailure(connectAuthority, rt, err)
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
					// Only when something survives the narrowing. A client
					// offering nothing this proxy can carry would otherwise be
					// answered with no ALPN at all, which is worse than being
					// offered a protocol it did not ask for and refusing it.
					if narrowed := httpALPN(hello.SupportedProtos); len(narrowed) > 0 {
						mirrored.NextProtos = narrowed
					}
				}
			}
			return mirrored, nil
		}
	} else {
		cfg.NextProtos = []string{"h2", "http/1.1"}
	}

	// The peek deadline was cleared once the tunnel kind was decided, so the
	// handshake needs its own: it reads the rest of the ClientHello, and a peer
	// that stops mid-record would otherwise block here indefinitely. Cleared
	// again below so it cannot cut short the traffic that follows.
	clientConn.SetDeadline(time.Now().Add(mitmHandshakeTimeout))

	tlsConn := tls.Server(clientConn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[vtunnel-proxy] MITM %s: TLS handshake failed: %v", connectAuthority, err)
		// A client that refuses the generated leaf is pinning certificates, and
		// will refuse it again on every retry. Record that so the next request
		// takes the pipe instead of failing the same way.
		p.noteMITMFailure(connectAuthority, rt, err)
		if up != nil {
			up.close()
		}
		clientConn.Close()
		return
	}
	clientConn.SetDeadline(time.Time{}) // the traffic that follows sets its own pace

	defer tlsConn.Close()
	// Releases the pre-established upstream only if no request ever claimed it.
	defer func() {
		if up != nil {
			up.close()
		}
	}()

	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		p.serveH2(tlsConn, connectAuthority, rt, up)
		return
	}
	p.serveH1(tlsConn, connectAuthority, rt, up)
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
	if err := handshakeWithTimeout(ctx, conn); err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// handshakeWithTimeout bounds an upstream TLS handshake. Every context this
// proxy has to hand — a request's, a client handshake's — may carry no deadline
// at all, and crypto/tls will wait on a silent peer forever without one.
func handshakeWithTimeout(ctx context.Context, conn *tls.Conn) error {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	return conn.HandshakeContext(ctx)
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
	// Logging only the client half would leave the upstream leg unreadable, so
	// the session still could not be followed end to end. A writer the caller
	// configured wins.
	if cfg.KeyLogWriter == nil {
		cfg.KeyLogWriter = tlsKeyLogWriter()
	}

	// Notice an upstream asking for a client certificate, without changing what
	// happens when it does. gomitmproxy returns an error from this hook to make
	// the request distinguishable, but that also fails every upstream whose
	// ClientAuth is merely RequestClientCert — those accept an empty
	// certificate, which is exactly what crypto/tls sends by default and what is
	// returned here. The flag only matters if the handshake then fails anyway.
	var clientCertRequested atomic.Bool
	if cfg.Certificates == nil && cfg.GetClientCertificate == nil {
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			clientCertRequested.Store(true)
			return &tls.Certificate{}, nil
		}
	}

	dialer := &net.Dialer{Timeout: dialTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, cfg)
	// dialer.Timeout covers the TCP connect and nothing else, and ctx here is
	// the client handshake's, which carries no deadline. This runs from inside
	// GetConfigForClient, blocked reading the upstream socket, so the deadline
	// armed on the client connection cannot fire either: an upstream that
	// accepts TCP and then goes quiet parked the goroutine and both file
	// descriptors for good, beyond the reach of Shutdown.
	if err := handshakeWithTimeout(ctx, conn); err != nil {
		raw.Close()
		if clientCertRequested.Load() {
			err = fmt.Errorf("%w: %w", errClientCertRequested, err)
		}
		return nil, err
	}

	// Pin what this handshake settled on before the config is reused for a
	// redial. The transport is chosen once, from the first connection's
	// protocol; leaving the full offer in place lets a later connection
	// negotiate something else — http/1.1 under an http2.Transport that is
	// waiting for h2 — and the session breaks on reconnect rather than at setup.
	if proto := conn.ConnectionState().NegotiatedProtocol; proto != "" {
		cfg.NextProtos = []string{proto}
	}
	return &upstreamTLSConn{addr: target, cfg: cfg, conn: conn}, nil
}

// upstreamRoundTripper builds the transport for a pre-established upstream TLS
// connection, matching whichever protocol that connection actually negotiated.
// The client may have settled on a different one — this proxy re-issues
// requests, so the two sides need not agree.
//
// This one cannot be shared: it is bound to a single connection, and so it
// lives and dies with it. The returned function is what releases it.
func (p *MITMProxy) upstreamRoundTripper(up *upstreamTLSConn) (http.RoundTripper, func()) {
	if up.proto() == "h2" {
		transport := &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return up.dial(ctx)
			},
		}
		return transport, transport.CloseIdleConnections
	}
	transport := p.transport.Clone()
	transport.ForceAttemptHTTP2 = false
	transport.DialContext = nil
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return up.dial(ctx)
	}
	return transport, transport.CloseIdleConnections
}

// upstreamKey identifies a transport that may be shared. Everything that
// changes how the connection is made belongs in it: two routes reaching the
// same address over different SNI, or one preferring h2 where the other does
// not, must not end up on the same pool.
type upstreamKey struct {
	target  string
	tlsHost string
	h2      bool
}

// cachedTransport returns the shared transport for key, building it once.
func (p *MITMProxy) cachedTransport(key upstreamKey, build func() http.RoundTripper) http.RoundTripper {
	p.upstreamsMu.Lock()
	defer p.upstreamsMu.Unlock()

	if transport, ok := p.upstreams[key]; ok {
		return transport
	}
	if p.upstreams == nil {
		p.upstreams = make(map[upstreamKey]http.RoundTripper)
	}
	transport := build()
	p.upstreams[key] = transport
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
// It runs through an http.Server passed to http2.ConfigureServer rather than a
// bare http2.Server, because that is the only thing that arms graceful
// shutdown: x/net/http2 keeps the machinery on Server.state, which nothing but
// ConfigureServer fills in, and shutdownNested can only reach an *http.Server
// anyway. Without it a live intercepted h2 session — a gRPC channel, an idle
// keep-alive'd connection — never received GOAWAY, ServeConn never returned,
// and Shutdown could do nothing but sit out its whole deadline and then cut the
// session off. The MITM config offers h2 first, so this is the common case.
func (p *MITMProxy) serveH2(clientConn net.Conn, authority string, rt route, up *upstreamTLSConn) {
	handler, release := p.routeHandler(authority, rt, up, true)
	defer release()

	h1srv := &http.Server{ReadHeaderTimeout: serverReadHeaderTimeout}
	h2srv := &http2.Server{}
	if err := http2.ConfigureServer(h1srv, h2srv); err != nil {
		log.Printf("[vtunnel-proxy] MITM %s: configure HTTP/2 server: %v", authority, err)
		return
	}
	defer p.trackNested(h1srv)()

	h2srv.ServeConn(clientConn, &http2.ServeConnOpts{
		BaseConfig: h1srv,
		Handler:    handler,
	})
}

// routeHandler turns a route into the handler that serves it: the caller's own
// handler for an in-process route, or a reverse proxy to its target. Both are
// wrapped in the configured middleware, so a Use hook sees every request the
// proxy terminates regardless of where it ends up.
func (p *MITMProxy) routeHandler(authority string, rt route, up *upstreamTLSConn, preferH2 bool) (http.Handler, func()) {
	release := func() {}
	var h http.Handler
	if rt.handler != nil {
		h = rt.handler
	} else {
		h, release = p.forwardingHandler(authority, rt, up, preferH2)
	}

	// A handler route performs its own upgrade — it holds the ResponseWriter and
	// can hijack it. A target route has to be spliced to that target instead.
	upgrade := h
	if rt.handler == nil {
		upgrade = p.upgradeHandler(authority, rt, up)
	}

	inject := rt.headers
	// The route — and with it the target and the credential — was chosen from
	// the authority this connection was opened for. Every request inside it
	// carried its own Host, so a sandbox could open one CONNECT to a domain it
	// is allowed to reach and then aim the injected credential at any other
	// virtual host that upstream serves. RFC 9110 §7.2 requires the two to
	// agree, and 421 is the answer for when they do not.
	expectHost := hostFromAuthority(authority)

	return p.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RequestURI = ""

		if expectHost != "" && !strings.EqualFold(hostFromAuthority(r.Host), expectHost) {
			log.Printf("[vtunnel-proxy] %s %s: Host %q does not match the authority this connection was opened for; refused",
				r.Method, authority, r.Host)
			http.Error(w, "vtunnel: request Host does not match the connection authority", http.StatusMisdirectedRequest)
			return
		}

		// HTTP/2 has no Upgrade mechanism — Connection and Upgrade are forbidden
		// (RFC 7540 §8.1.2.2) and x/net/http2 rejects such a request before it
		// reaches here — so this is an HTTP/1.1 concern only. That also settles
		// the ResponseWriter question: only the HTTP/1.1 path can hijack.
		if !preferH2 && isUpgradeRequest(r) {
			removeHopByHopForUpgrade(r.Header)
			injectConfiguredHeaders(r.Header, inject)
			upgrade.ServeHTTP(w, r)
			return
		}

		removeHopByHop(r.Header, preferH2)
		injectConfiguredHeaders(r.Header, inject)
		h.ServeHTTP(w, r)
	})), release
}

// upgradeHandler splices a protocol upgrade through to the route's target.
func (p *MITMProxy) upgradeHandler(authority string, rt route, up *upstreamTLSConn) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[vtunnel-proxy] %s %s -> %s (%s upgrade)", r.Method, authority, rt.target, r.Header.Get("Upgrade"))

		upstream, err := p.dialUpstreamConn(r.Context(), rt, up)
		if err != nil {
			p.noteMITMFailure(authority, rt, err)
			log.Printf("[vtunnel-proxy] upgrade %s -> %s failed: %v", authority, rt.target, err)
			http.Error(w, "vtunnel: upstream connection failed", http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		defer p.track(upstream)()

		serveUpgrade(w, r, upstream, false, p.track)
	})
}

// dialUpstreamConn opens a raw connection to target, making the same choices
// upstreamTransport does but handing back the connection itself: an upgrade is
// spliced, not round-tripped, so there is nothing for a RoundTripper to do.
func (p *MITMProxy) dialUpstreamConn(ctx context.Context, rt route, up *upstreamTLSConn) (net.Conn, error) {
	target := rt.target
	// A pre-established upstream is reusable only if it settled on HTTP/1.1.
	// An upgrade cannot be expressed over h2, so an h2 connection is no use here
	// and a fresh one is dialled instead.
	if up != nil && up.proto() != "h2" {
		return up.dial(ctx)
	}

	tlsHost, upstreamIsTLS := rt.tlsHost, rt.tlsHost != ""

	dialer := &net.Dialer{Timeout: dialTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	if !upstreamIsTLS {
		return raw, nil
	}

	cfg := &tls.Config{}
	if p.transport.TLSClientConfig != nil {
		cfg = p.transport.TLSClientConfig.Clone()
	}
	cfg.ServerName = tlsHost
	// Only HTTP/1.1 is offered: negotiating h2 would land the handshake we are
	// about to write on a connection where it is not even legal.
	cfg.NextProtos = []string{"http/1.1"}
	if cfg.KeyLogWriter == nil {
		cfg.KeyLogWriter = tlsKeyLogWriter()
	}

	conn := tls.Client(raw, cfg)
	if err := handshakeWithTimeout(ctx, conn); err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// forwardingHandler re-issues a decrypted request to the route's target. The
// second return releases the transport; the caller must defer it.
func (p *MITMProxy) forwardingHandler(authority string, rt route, up *upstreamTLSConn, preferH2 bool) (http.Handler, func()) {
	target := rt.target
	transport, scheme, release := p.upstreamTransport(rt, up, preferH2)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Scheme = scheme
		r.URL.Host = target

		resp, err := transport.RoundTrip(r)
		if err != nil {
			// TLS 1.3 sends the client certificate after the handshake has
			// otherwise completed, so an upstream that requires one accepts the
			// handshake and only rejects on the first exchange — here, not in
			// dialTLSUpstream. Same for an upstream whose own certificate does
			// not check out on a connection dialled later.
			p.noteMITMFailure(authority, rt, err)
			// Logged, not returned: the answer crosses the tunnel, and a
			// transport error names the controlplane-internal target it was
			// trying to reach.
			log.Printf("[vtunnel-proxy] %s %s -> %s failed: %v", r.Method, authority, target, err)
			http.Error(w, "vtunnel: upstream request failed", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// Trailers, announced and unannounced alike, are copyResponse's job:
		// announcing here would put the names in the header map just before the
		// hop-by-hop sweep inside it deleted them again.
		copyResponse(w, resp)
	}), release
}

// upstreamTransport picks how to reach target and which scheme that implies.
// The third return releases the transport, and does nothing for the shared
// ones; the caller must defer it.
func (p *MITMProxy) upstreamTransport(rt route, up *upstreamTLSConn, preferH2 bool) (http.RoundTripper, string, func()) {
	target := rt.target
	if up != nil {
		// Upstream TLS is already up and negotiated; reuse it instead of
		// handshaking a second time.
		transport, release := p.upstreamRoundTripper(up)
		return transport, "https", release
	}

	noRelease := func() {}

	if tlsHost := rt.tlsHost; tlsHost != "" {
		// Proxy-side TLS: dial the target, then handshake using the real
		// server's hostname for SNI.
		transport := p.cachedTransport(upstreamKey{target: target, tlsHost: tlsHost, h2: preferH2}, func() http.RoundTripper {
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
			if transport.TLSClientConfig.KeyLogWriter == nil {
				transport.TLSClientConfig.KeyLogWriter = tlsKeyLogWriter()
			}
			return transport
		})
		return transport, "https", noRelease
	}

	if preferH2 && p.probeH2C(target) {
		transport := p.cachedTransport(upstreamKey{target: target, h2: true}, func() http.RoundTripper {
			return &http2.Transport{
				AllowHTTP: true,
				DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
					return net.DialTimeout(network, addr, dialTimeout)
				},
			}
		})
		return transport, "http", noRelease
	}

	return &p.transport, "http", noRelease
}

// serveH1 serves a decrypted HTTP/1.1 connection through net/http, which brings
// keep-alive, chunking and trailer handling with it, and lets a handler route
// and a forwarded one run through exactly the same code.
func (p *MITMProxy) serveH1(clientConn net.Conn, authority string, rt route, up *upstreamTLSConn) {
	handler, release := p.routeHandler(authority, rt, up, false)
	defer release()

	// net/http reports TLS state by asserting the concrete *tls.Conn, and the
	// one-shot listener has to hand it a wrapper — so every request on an
	// intercepted connection looked like cleartext to handlers and middleware.
	// The state is known here, so it is filled in here.
	if tlsConn, ok := clientConn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		inner := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil {
				r.TLS = &state
			}
			inner.ServeHTTP(w, r)
		})
	}

	ln := newOneShotListener(clientConn)
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: serverReadHeaderTimeout,
	}
	// Registered so Shutdown can end this connection between requests instead of
	// cutting a response in half. Serve returns once the server closes the
	// connection, which is what releases the one-shot listener.
	defer p.trackNested(srv)()

	_ = srv.Serve(ln)
	// Serve returns as soon as the listener closes, which Shutdown does first.
	// The caller closes the connection once this returns, so wait for net/http
	// to actually be finished with it rather than cutting a response short.
	ln.wait()
}

// oneShotListener hands one already-established connection to net/http. The
// second Accept blocks until that connection is done, so Serve does not return
// while the connection is still being used.
// Two events have to be told apart, which is why there are two channels.
//
// Accept must unblock when the listener is closed, or http.Server.Shutdown
// deadlocks: it waits for its own Serve goroutine to return before it starts
// honouring ctx, and that goroutine is parked in Accept. But once Accept can
// return early, Serve returning is no longer proof that the connection is
// finished — and the caller closes the connection as soon as it is. Closing it
// under a handler that is still writing truncates the response, so completion
// is reported separately by the connection itself.
type oneShotListener struct {
	conn net.Conn

	mu        sync.Mutex
	handedOut bool
	closed    bool

	connOnce sync.Once
	closedCh chan struct{} // the listener was closed
	connDone chan struct{} // net/http is finished with the connection
}

func newOneShotListener(conn net.Conn) *oneShotListener {
	return &oneShotListener{
		conn:     conn,
		closedCh: make(chan struct{}),
		connDone: make(chan struct{}),
	}
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.handedOut && !l.closed {
		l.handedOut = true
		l.mu.Unlock()
		return &notifyConn{Conn: l.conn, release: l.markConnDone}, nil
	}
	l.mu.Unlock()

	select {
	case <-l.connDone:
	case <-l.closedCh:
	}
	return nil, io.EOF
}

func (l *oneShotListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	handedOut := l.handedOut
	l.mu.Unlock()

	close(l.closedCh)
	if !handedOut {
		// Serve never took the connection, so nothing will ever report it
		// finished; say so here or wait would block forever.
		l.markConnDone()
	}
	return nil
}

func (l *oneShotListener) markConnDone() {
	l.connOnce.Do(func() { close(l.connDone) })
}

// wait blocks until net/http is done with the connection, which is the point at
// which the caller may close it.
func (l *oneShotListener) wait() { <-l.connDone }

func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

// notifyConn signals when net/http is finished with the connection.
type notifyConn struct {
	net.Conn
	release func()
}

func (c *notifyConn) Close() error {
	err := c.Conn.Close()
	c.release()
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
	handler, release := p.routeHandler(hostPort, rt, nil, false)
	defer release()
	handler.ServeHTTP(w, r)
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
func (p *MITMProxy) dialAndPipe(target string, clientConn net.Conn) {
	targetConn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		log.Printf("[vtunnel-proxy] dial %s failed: %v", target, err)
		return
	}
	defer targetConn.Close()
	defer p.track(targetConn)()

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
