package vtunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
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

// clientFirstByteGrace is how long a tunnel waits for the client to say
// something before it starts asking the upstream instead. Every client that
// speaks first does so within a round trip of the CONNECT it just read, so this
// only has to be longer than that; past it, silence is worth investigating
// rather than waiting out.
const clientFirstByteGrace = 250 * time.Millisecond

// tunnelSegmentGrace bounds the wait for the rest of something the client has
// already started saying. That is a different wait from the one above: the
// message is half-delivered and the remainder is a round trip away at most, so
// waiting out the whole peekTimeout for it would park a connection on a request
// line that is never going to be finished.
const tunnelSegmentGrace = time.Second

// peekTimeout bounds the wait for the client's first tunnel byte, so an idle
// CONNECT can't park a goroutine and fd indefinitely. It bounds the sandbox
// egress proxy's SOCKS5 handshake too — a greeting that stops halfway is the same
// shape of idle client. A variable rather than a constant so a test can prove
// the bound is applied instead of waiting one out.
var peekTimeout = newDurationVar(30 * time.Second)

// durationVar is a duration a test may change while the proxy is running.
// Reading it through an atomic is not about which of the two values a given
// connection sees — either is fine — but about the alternative, which is a data
// race with every connection being served at that moment.
type durationVar struct{ nanos atomic.Int64 }

func newDurationVar(d time.Duration) *durationVar {
	v := &durationVar{}
	v.Set(d)
	return v
}

func (v *durationVar) Get() time.Duration  { return time.Duration(v.nanos.Load()) }
func (v *durationVar) Set(d time.Duration) { v.nanos.Store(int64(d)) }

// dialTimeout bounds every upstream dial the proxy makes.
const dialTimeout = 10 * time.Second

// mitmHandshakeTimeout bounds the client's TLS handshake once the peek deadline
// has been cleared. Without it a client that sends a record header and then
// stops holds a goroutine and a file descriptor for the life of the process:
// peekTimeout only ever covered the wait for the first byte.
//
// A variable rather than a constant so tests need not wait it out.
var mitmHandshakeTimeout = newDurationVar(30 * time.Second)

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
//
// A variable rather than a constant so tests need not wait it out, as
// connectReplyTimeout already is.
var serverReadHeaderTimeout = newDurationVar(30 * time.Second)

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
//   - neither — the target is the host the client asked for ([MITMProxy.Forward]).
//     Filled in per request, so it is terminated like any other route when
//     there is a CA and piped when there is not.
type route struct {
	handler http.Handler
	target  string
	headers http.Header
	// cleartext records that the target was declared cleartext ("http://" or
	// "h2c://"), rather than merely written without a scheme. The difference
	// matters only for a route that injects headers: an unstated scheme is asked
	// about before the credential is written, a stated one is taken at its word.
	cleartext bool
	// h2c records that the target was declared cleartext HTTP/2 ("h2c://"), so
	// the upstream is spoken to that way without being asked and whatever the
	// client side settled on.
	h2c bool
	// targetPortFromRequest records that the target named no port, so the port
	// dialled is the one the client asked for. It is resolved into target the
	// moment a request picks the route up, before anything branches on the
	// address, so nothing downstream has to know a port was ever missing.
	targetPortFromRequest bool
	// selfTarget records that target was filled in from the authority the
	// client asked for rather than configured — a [MITMProxy.Forward] route,
	// served by a proxy that holds a CA.
	//
	// Such a route says where to go and nothing about how, so it follows the
	// client: TLS inside the tunnel means TLS to the upstream, cleartext means
	// cleartext. A configured target is the opposite — it says how, and the two
	// legs are then independent.
	selfTarget bool
	// generation tells one revision of a route from another, so a connection
	// that resolved this route when it opened can notice that the answer has
	// changed since. Comparing the routes themselves would not do: a handler is
	// not comparable, and two revisions may differ only in a header map.
	generation uint64
	// tlsHost is the server name to present when opening TLS to target, empty
	// when the target is reached in the clear.
	//
	// It lives on the route rather than in a map keyed by address because two
	// routes may share an address and disagree about it — one tls://, one not —
	// and a map could then hand the wrong answer to whichever asked second, or
	// keep a stale mark alive after the route that set it was replaced.
	tlsHost string
}

// withRequestPort fills in a target that named no port, from the authority the
// request was aimed at. A route written "api.corp=gw.internal" says which host
// to reach and leaves the port to the request, and resolving that here — once,
// before anything branches on the address — is what keeps every path that dials,
// pipes, probes or pools a target from having to know a port was ever missing.
func (r route) withRequestPort(authority string) route {
	if !r.targetPortFromRequest || r.target == "" {
		return r
	}
	if _, _, err := net.SplitHostPort(r.target); err == nil {
		return r // already carrying one
	}
	r.target = net.JoinHostPort(r.target, portFromAuthority(authority))
	return r
}

// followClientScheme fills in the upstream server name for a route that named a
// host but not how to reach it, from what the client turned out to be speaking.
//
// A route whose port came from the request is in the same position as one with
// no target at all: it says which host, and nothing about how. The port used to
// carry that — a target on ":443" means TLS — so a target written without one
// has to learn it from the client instead, or "gitlab.corp=gitlab.corp" talks
// cleartext to an HTTPS upstream and the reply is an error page. A stated
// scheme, a [WithSNI] name and a target carrying its own port each say how, and
// none of them is overridden here.
//
// It runs once the tunnel has been classified rather than when the target was
// filled in, because until then there was nothing to follow.
func (r route) followClientScheme(clientIsTLS bool) route {
	if !clientIsTLS || r.cleartext || r.tlsHost != "" {
		return r
	}
	if !r.selfTarget && !r.targetPortFromRequest {
		return r
	}
	r.tlsHost = hostFromAuthority(r.target)
	return r
}

// terminates reports whether serving this route means decrypting the client's
// TLS, which requires a CA.
func (r route) terminates() bool { return r.handler != nil || r.target != "" }

// canFallBack reports whether this route may quietly degrade to a byte pipe
// when interception turns out to be impossible. It needs somewhere to pipe to,
// it must not be carrying headers — a route that stopped injecting a credential
// but kept working would hide the failure instead of surfacing it — and it must
// not be renaming the server, which a pipe cannot do.
func (r route) canFallBack(authority string) bool {
	if r.target == "" || len(r.headers) > 0 {
		return false
	}
	// A route that renames the server cannot be piped either. The pipe carries
	// the client's own name, not the configured one, so it goes to an upstream
	// whose TLS identity was never negotiated for it — it cannot succeed, and
	// it replaces an accurate and fixable error ("this upstream's certificate
	// does not check out") with a misleading one about a domain that is not the
	// problem.
	return r.tlsHost == "" || strings.EqualFold(r.tlsHost, hostFromAuthority(authority))
}

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
	onChange   []func()
	domainMu   sync.RWMutex
	// routeGeneration stamps every revision of every route, so a connection can
	// tell that the route it resolved when it opened is no longer the answer.
	routeGeneration atomic.Uint64

	// mitmCA is the CA used to sign generated leaf certificates
	// (nil = transparent tunnel, no interception).
	mitmCA        *tls.Certificate
	certCacheOnce sync.Once
	certCacheVal  *certCache
	certCacheErr  error

	transport http.Transport
	h2cProbes probeCache

	// tlsProbes remembers which upstreams answered a ClientHello, for targets
	// written without a scheme on routes that carry a credential.
	tlsProbes probeCache

	tlsBaseMu    sync.Mutex
	tlsBaseCfg   *tls.Config
	ticketKeys   [][32]byte
	ticketKeysAt time.Time

	// preDial bounds the upstream connections opened from inside client
	// handshakes; see maxPendingUpstreamDials.
	preDialOnce sync.Once
	preDial     chan struct{}

	// upstreams holds one transport per distinct upstream. Building one per
	// request looked harmless and leaked: a clone of a zero-value
	// http.Transport inherits IdleConnTimeout 0, so net/http never arms its
	// idle reaper, and the clone goes out of scope after RoundTrip with nobody
	// left to call CloseIdleConnections — an idle connection plus its read and
	// write goroutines then live until the process exits. Keep-alive never
	// worked either, since every request opened a fresh connection. EgressProxy
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
	// stopping is set once the wait on detachedWg has begun, under detachedMu,
	// so registering and closing cannot race that wait.
	stopping bool

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
		ReadHeaderTimeout: serverReadHeaderTimeout.Get(),
		// net/http answers `OPTIONS *` itself unless told not to. That request
		// asks about the server the client is talking to, and inside an
		// intercepted connection that server is the origin, not this proxy — so
		// a built-in 200 here is the proxy answering on the origin's behalf,
		// with no route lookup, no injected credential and no upstream.
		DisableGeneralOptionsHandler: true,
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
	p.stopTracking()
	ln, srv := p.lifecycle()
	if srv != nil {
		srv.Close()
	}
	// The listener is closed here as well as by the server. http.Server only
	// knows the listeners Serve has registered with it, and Start hands this one
	// to a goroutine — so a Close that lands before that goroutine is scheduled
	// finds nothing to close, and the port goes on accepting until it is. Rare,
	// and rare is worse than never: the call returned saying it had stopped.
	if ln != nil {
		ln.Close()
	}
	p.closeDetached()
	p.closeIdleUpstreams()
}

// stopTracking closes the registry to new arrivals. After this a connection
// that was in flight registers nothing and is told so, which is what keeps it
// from adding to a WaitGroup somebody is already waiting on.
func (p *MITMProxy) stopTracking() {
	p.detachedMu.Lock()
	p.stopping = true
	p.detachedMu.Unlock()
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
	}
	// For the same reason Close does it: a listener Serve has not registered yet
	// is not one the server can be asked to stop.
	if ln != nil {
		ln.Close()
	}
	<-nestedDone

	// http.Server.Shutdown knows nothing about hijacked connections — the whole
	// point of hijacking is that the server hands ownership over — so the
	// detached ones are waited on separately.
	//
	// Closed to new arrivals first: from here on nothing may join the group. A
	// connection that registered after the wait began would be adding to a
	// counter that had already reached zero, which a WaitGroup answers with a
	// panic rather than by waiting a little longer.
	p.stopTracking()

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

	closeIdleTransports(p.snapshotUpstreams(false))
}

// snapshotUpstreams copies the cached transports out from under the lock so
// they can be closed without holding it, emptying the cache when drop is set.
func (p *MITMProxy) snapshotUpstreams(drop bool) []http.RoundTripper {
	p.upstreamsMu.Lock()
	defer p.upstreamsMu.Unlock()

	transports := make([]http.RoundTripper, 0, len(p.upstreams))
	for _, t := range p.upstreams {
		transports = append(transports, t)
	}
	if drop {
		clear(p.upstreams)
	}
	return transports
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
	release, _ := p.trackIfOpen(c)
	return release
}

// trackIfOpen registers a connection unless the proxy is already shutting down,
// reporting whether it did.
//
// The check and the Add are one step on purpose. Shutdown waits on this counter,
// and a connection that passed a closed() check a moment earlier would add to a
// counter that had already reached zero and was being waited on — which is not
// a slow shutdown but a panic, because a WaitGroup may not be reused before its
// Wait returns.
func (p *MITMProxy) trackIfOpen(c io.Closer) (release func(), ok bool) {
	p.detachedMu.Lock()
	if p.stopping {
		p.detachedMu.Unlock()
		return func() {}, false
	}
	p.detachedWg.Add(1)
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
	}, true
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

// Forward routes a domain through this proxy. Without [WithTarget] the target
// is the host the client asked for, filled in per request — which is what lets
// one wildcard stand for a family of hosts, each reaching itself.
//
// The domain may be a hostname, a wildcard, or either with a port, and it means
// the same thing whatever the route does with it: written without a port it
// covers every port of that name. A wildcard is as legal with a target as
// without one — `*.corp` with no target sends every host under it to itself,
// and with [WithTarget]("gw.internal") sends all of them to one gateway, on
// whichever port each was asked for.
//
// How the target is reached can be stated or left to be discovered:
//
//	localhost:8080        asked about, if the route carries a header
//	tls://host[:port]     TLS, SNI from the host
//	h2c://host[:port]     cleartext HTTP/2, so nothing is probed for it
//	http://host[:port]    cleartext, and do not ask
//
// Discovery is the right default for an address somebody typed, and it is not
// free. An unstated scheme on a route that injects a credential costs a probe
// before the first request, because writing the credential to find out is the
// one thing that must not happen. And h2c is only ever looked for when the
// client side is HTTP/2 as well, so an h2c-only upstream behind an HTTP/1.1
// client is reachable by saying "h2c://" and not otherwise.
//
// A target written without a port is dialled on the port the client asked for,
// and follows the client on protocol too — the port is what used to say TLS, so
// with none to read it off the answer comes from the same place the port does.
//
// What happens to the client's TLS follows the proxy, not the route. With a CA
// it is terminated like any other route, so middleware and [WithHeader] apply;
// with no CA there is nothing to terminate with and the bytes are piped. An
// upstream that must not be intercepted — one the client pins, or something
// that is not HTTP — is [MITMProxy.MITMExceptions], which is also what the
// proxy records for itself after a handshake that could not have worked.
//
// Injecting a header needs a CA and a route carrying one is refused without it,
// rather than answering requests perfectly normally and never adding the
// credential — a failure with no error to see. "h2c://" and [WithSNI]
// contradict each other and are refused together: one is cleartext, the other
// names the server for a TLS handshake.
func (p *MITMProxy) Forward(domain string, opts ...ForwardOption) error {
	cfg := forwardConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	if len(cfg.headers) > 0 && p.mitmCA == nil {
		return fmt.Errorf("forward %s: %d configured header(s) need a MITM CA, %w",
			domain, len(cfg.headers), errNoMitmCA)
	}
	if cfg.sni != "" && strings.HasPrefix(cfg.target, "h2c://") {
		return fmt.Errorf("forward %s: WithSNI names the server for a TLS handshake, and an "+
			"h2c:// target is cleartext; drop one of the two", domain)
	}

	if cfg.target == "" {
		p.setRoute(domain, route{headers: cfg.headers, tlsHost: cfg.sni},
			"the host the client asked for")
		return nil
	}

	t, ok := parseRouteTarget(cfg.target)
	if !ok {
		// A scheme and nothing else. Left alone this becomes a dial to an empty
		// host, which in Go is this machine — so it is refused where it is
		// written rather than discovered as a connection to the wrong place.
		return fmt.Errorf("forward %s: target %q names no host", domain, cfg.target)
	}
	if cfg.sni != "" {
		t.tlsHost = cfg.sni
	}
	// Both stated schemes are cleartext, and stating one is what excuses the
	// route from being asked whether its upstream speaks TLS.
	cleartext := strings.HasPrefix(cfg.target, "http://") || t.h2c
	p.setRoute(domain, route{
		target:                t.host,
		targetPortFromRequest: t.portFromRequest,
		headers:               cfg.headers,
		tlsHost:               t.tlsHost,
		cleartext:             cleartext,
		h2c:                   t.h2c,
	}, describeTarget(t))
	return nil
}

// ForwardTo is [MITMProxy.Forward] with [WithTarget], and exists because a
// target is where a request goes rather than a detail of how it gets there:
// at a call site somebody writes by hand it belongs where it can be read.
// Building the options up instead — a CLI turning flags into a route — is what
// WithTarget is for.
func (p *MITMProxy) ForwardTo(domain, target string, opts ...ForwardOption) error {
	if target == "" {
		return fmt.Errorf("forward %s: empty target; use Forward to route a domain to itself", domain)
	}
	// Appended to a copy, since append to the caller's own slice can write into
	// the array behind it. Last wins, so the argument this method is named for
	// is the one that decides.
	return p.Forward(domain, append(slices.Clone(opts), WithTarget(target))...)
}

// describeTarget renders a target for the route log, saying so when the port is
// not the route's to name.
func describeTarget(t forwardTarget) string {
	if t.portFromRequest {
		return t.host + ":<the port asked for>"
	}
	return t.host
}

// Remove drops a domain's route.
func (p *MITMProxy) Remove(domain string) {
	p.domainMu.Lock()
	var targets []upstreamTarget
	if rt, ok := p.routes[domain]; ok && rt.target != "" {
		targets = append(targets, upstreamTarget{addr: rt.target, anyPort: rt.targetPortFromRequest})
	}
	delete(p.routes, domain)
	changed := p.changedLocked()
	p.domainMu.Unlock()

	// The pooled connections to that target go with it. Left behind they are a
	// socket and a read goroutine held open for somewhere nothing routes to any
	// more — and for an h2c upstream, one that is never retired for idleness
	// either, since a bare http2.Transport has no idle timeout to reach.
	p.dropUpstreams(targets)

	log.Printf("[vtunnel-proxy] Route removed: %s", domain)
	notify(changed)
}

// upstreamTarget names the upstream connections a route owned, so that they go
// when it does. A route whose port came from the request pooled one transport
// per port that was ever asked for, and its address alone does not name any of
// them.
type upstreamTarget struct {
	addr    string
	anyPort bool
}

func (t upstreamTarget) matches(target string) bool {
	if !t.anyPort {
		return target == t.addr
	}
	host, _, err := net.SplitHostPort(target)
	return err == nil && host == t.addr
}

// dropUpstreams closes and forgets the cached transports for the given targets.
func (p *MITMProxy) dropUpstreams(targets []upstreamTarget) {
	if len(targets) == 0 {
		return
	}

	p.upstreamsMu.Lock()
	var stale []http.RoundTripper
	for key, transport := range p.upstreams {
		if slices.ContainsFunc(targets, func(t upstreamTarget) bool { return t.matches(key.target) }) {
			stale = append(stale, transport)
			delete(p.upstreams, key)
		}
	}
	p.upstreamsMu.Unlock()

	closeIdleTransports(stale)
}

// closeIdleTransports drops the idle connections each transport is holding. Not
// every RoundTripper can — a caller-supplied one need not be an http.Transport.
func closeIdleTransports(transports []http.RoundTripper) {
	for _, t := range transports {
		if idler, ok := t.(interface{ CloseIdleConnections() }); ok {
			idler.CloseIdleConnections()
		}
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
//
// Callbacks accumulate. One proxy shared between clients — which [WithProxy]
// exists for — means one subscriber per client, and a single slot made the
// second registration cancel the first: that client's sandbox went on holding
// whatever allowlist it had when it last heard anything, with no error to say so.
func (p *MITMProxy) OnChange(f func()) {
	if f == nil {
		return
	}
	p.domainMu.Lock()
	p.onChange = append(p.onChange, f)
	p.domainMu.Unlock()
}

// changed returns the callbacks to fire, copied so they can be called with no
// lock held — a subscriber is free to read routes, or add one.
func (p *MITMProxy) changedLocked() []func() {
	return append([]func(){}, p.onChange...)
}

func notify(callbacks []func()) {
	for _, f := range callbacks {
		f()
	}
}

func (p *MITMProxy) setRoute(domain string, rt route, describe string) {
	rt.generation = p.routeGeneration.Add(1)

	p.domainMu.Lock()
	p.routes[domain] = rt
	changed := p.changedLocked()
	p.domainMu.Unlock()

	log.Printf("[vtunnel-proxy] Route: %s -> %s", domain, describe)
	notify(changed)
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

	closeIdleTransports(p.snapshotUpstreams(true))
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
		p.noMITM[domain] = time.Time{} // zero: no expiry
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

	if !rt.canFallBack(authority) {
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

// resolveDomain finds the route serving an authority, with a target that named
// no port filled in from it. Every caller resolves through here, so none of
// them sees a half-finished route.
func (p *MITMProxy) resolveDomain(host string) (route, bool) {
	p.domainMu.RLock()
	defer p.domainMu.RUnlock()

	pattern, ok := bestDomainMatch(p.routes, host)
	if !ok {
		return route{}, false
	}
	return p.routes[pattern].withRequestPort(host), true
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

	if !isRoutableAuthority(hostPort) {
		log.Printf("[vtunnel-proxy] CONNECT %q: not a host and port; refused", hostPort)
		http.Error(w, "vtunnel: CONNECT authority is not a host and port", http.StatusBadRequest)
		return
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

	// A route with no target of its own means "go to the host you asked for",
	// and on a proxy holding a CA that is still terminated. Anything routed
	// through this proxy is decrypted if it can be: that is what the CA is for,
	// and it is what makes middleware, in-process handlers and the injected
	// credential apply uniformly instead of depending on which spelling of a
	// route somebody picked.
	//
	// The cleartext path has always done this — see handleHTTP, which fills in
	// the same target — so before this the same route was re-issued on :80 and
	// piped on :443.
	//
	// An upstream that must not be intercepted is still reachable, and now says
	// so explicitly: MITMExceptions, or the exclusion the proxy learns for
	// itself from a handshake that could not have worked.
	if isRouted && certs != nil && rt.target == "" && rt.handler == nil {
		rt.target, rt.selfTarget = hostPort, true
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
		case rt.canFallBack(hostPort):
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
	//
	// With a CA configured, reaching here for a routed domain means the
	// interception that would otherwise have happened was excepted — so the log
	// says which of the two it is rather than announcing "untouched", which on
	// an intercepting proxy reads as a contradiction.
	target := hostPort
	switch {
	case isRouted && rt.selfTarget:
		log.Printf("[vtunnel-proxy] CONNECT %s -> itself, not intercepted", hostPort)
	case isRouted && rt.target != "":
		target = rt.target
		log.Printf("[vtunnel-proxy] CONNECT %s -> %s, not intercepted", hostPort, target)
	case isRouted:
		log.Printf("[vtunnel-proxy] CONNECT %s -> itself, no MITM CA to intercept with", hostPort)
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
	deadline := time.Now().Add(peekTimeout.Get())
	rawConn.SetReadDeadline(time.Now().Add(clientFirstByteGrace))
	br := bufio.NewReaderSize(rawConn, maxRequestLinePeek)

	// Read once before deciding anything, so the padding check has something to
	// look at without waiting for more than the client sent.
	_, err := br.Peek(1)
	if err != nil && !isTimeout(err) {
		rawConn.SetReadDeadline(time.Time{})
		log.Printf("[vtunnel-proxy] CONNECT %s: peek client stream failed: %v", connectAuthority, err)
		rawConn.Close()
		return
	}

	// The client has said nothing. That is not evidence of anything on its own —
	// a protocol whose server greets first has nothing to say yet, and so has a
	// TLS client that is merely slow — so rather than guess, ask the upstream.
	// Silence proves nothing; a greeting proves the protocol is server-first.
	// This is mitmproxy's connection_strategy=eager, and its default.
	var eager *bufferedConn
	if err != nil && rt.target != "" && rt.canFallBack(connectAuthority) {
		var greeted bool
		eager, greeted = p.raceForFirstBytes(rawConn, br, rt.target, deadline)
		defer func() {
			// Closed unless the pipe below took it over.
			if eager != nil {
				eager.Close()
			}
		}()
		if greeted {
			log.Printf("[vtunnel-proxy] CONNECT %s -> %s: the upstream greeted first, piping",
				connectAuthority, rt.target)
			rawConn.SetReadDeadline(time.Time{})
			piped := eager
			eager = nil
			defer piped.Close()
			defer p.track(piped)()
			dualStream(piped, newBufferedConn(rawConn, br), rawConn)
			return
		}
	}
	// A client that has started speaking is held to the shorter bound; one that
	// has not is still owed the full wait, and for a route that may be piped the
	// race above is what ends it early.
	if br.Buffered() > 0 {
		deadline = time.Now().Add(tunnelSegmentGrace)
	}
	rawConn.SetReadDeadline(deadline)
	discardConnectPadding(br)

	kind := classifyTunnel(br)
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
	case kind == tunnelTLS:
		// The client is speaking TLS to the host it named, so this proxy speaks
		// TLS to the route's host under that host's own name.
		rt = rt.followClientScheme(true)
		p.serveMITMTLS(tunnelConn, connectAuthority, rt, certs)
	case kind == tunnelH2C && overHijackedSocket:
		defer tunnelConn.Close()
		log.Printf("[vtunnel-proxy] CONNECT %s: cleartext h2c, terminating", connectAuthority)
		// No pre-established upstream here: the client came in cleartext, so
		// there was no client handshake to mirror an upstream ALPN onto.
		p.serveH2(tunnelConn, connectAuthority, rt, nil)
	case kind == tunnelHTTP1 && overHijackedSocket:
		// Cleartext HTTP/1.1 inside the tunnel. Every SOCKS5 client arrives
		// this way — it has no CONNECT of its own, so the egress proxy makes one, and
		// `curl http://api.corp/` becomes CONNECT api.corp:80 followed by an
		// ordinary request.
		//
		// It is served rather than piped, which is what makes the answer the
		// same whichever door the client came through: a handler route is
		// served (piping would have nowhere to go, and this used to be closed
		// outright), and a target route gets its configured headers injected —
		// over a pipe they silently were not, so the same request carried the
		// credential through HTTP_PROXY and not through ALL_PROXY.
		//
		// Restricted to a hijacked socket for the same reason h2c is: a nested
		// server writing after the outer handler returned would be writing to a
		// response that no longer exists.
		defer tunnelConn.Close()
		log.Printf("[vtunnel-proxy] CONNECT %s: cleartext HTTP, terminating", connectAuthority)
		p.serveH1(tunnelConn, connectAuthority, rt, nil)
	case rt.handler != nil:
		// A handler route has no address to fall back to.
		defer tunnelConn.Close()
		log.Printf("[vtunnel-proxy] CONNECT %s: cleartext, but the route is served in process and this is not HTTP", connectAuthority)
	case !rt.canFallBack(connectAuthority):
		// A route carrying headers is never quietly downgraded to a pipe. The
		// same rule already governs the other way interception can turn out to
		// be impossible — an upstream that refuses it, see canFallBack — and
		// for the same reason: a request that works without the credential it
		// was configured to carry hides the failure instead of reporting it.
		defer tunnelConn.Close()
		log.Printf("[vtunnel-proxy] CONNECT %s: not HTTP, and this route injects %d header(s) a raw pipe cannot add; refused rather than forwarded without them",
			connectAuthority, len(rt.headers))
	case eager != nil:
		// Already dialled while waiting for this client to speak.
		defer tunnelConn.Close()
		log.Printf("[vtunnel-proxy] CONNECT %s -> %s (cleartext, raw pipe)", connectAuthority, rt.target)
		piped := eager
		eager = nil
		defer piped.Close()
		defer p.track(piped)()
		dualStream(piped, tunnelConn, tunnelConn)
	default:
		defer tunnelConn.Close()
		if br.Buffered() == 0 {
			// Neither side said anything before the deadline: nothing was ever
			// established about this tunnel, and a pipe is the only thing that
			// can be done with it. Worth a line, because the alternative is
			// finding out from the absence of something.
			log.Printf("[vtunnel-proxy] CONNECT %s -> %s: neither side spoke, piping",
				connectAuthority, rt.target)
		} else {
			log.Printf("[vtunnel-proxy] CONNECT %s -> %s (cleartext, raw pipe)", connectAuthority, rt.target)
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

	// Cloned from one long-lived config so session tickets outlive the
	// connection that issued them. Built fresh each time, the server's ticket
	// keys were new on every connection, so no client could ever resume and
	// every one of them paid a full handshake.
	base := p.tlsBase().Clone()
	base.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return certs.getCert(hello, connectHost)
	}

	var up *upstreamTLSConn
	cfg := base.Clone()
	if upstreamIsTLS {
		cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			// Dialling here is what lets the client be offered exactly what the
			// upstream negotiated — and it happens before the client has proved
			// anything, on nothing more than a ClientHello. A sandbox that sends
			// one and then stops therefore makes this proxy hold a connection
			// open into the controlplane's network, and with no cap it could
			// hold as many as it liked. Past the cap the mirroring is simply
			// skipped: the base ALPN stands and the request path dials as it
			// does for any cleartext route.
			release, ok := p.acquirePreDial()
			if !ok {
				log.Printf("[vtunnel-proxy] MITM %s: %d upstream handshakes already pending, "+
					"not pre-dialling this one", connectAuthority, cap(p.preDial))
				return nil, nil
			}
			defer release()

			u, err := p.dialTLSUpstream(hello.Context(), target, sniHost, hello.SupportedProtos)
			if err != nil {
				log.Printf("[vtunnel-proxy] MITM %s: upstream TLS to %s failed: %v", connectAuthority, target, err)
				// Noted here rather than only at the handshake below: the client
				// error this turns into says nothing about the upstream cause.
				p.noteMITMFailure(connectAuthority, rt, err)
				// The client's handshake completes anyway. Failing it here is
				// the only thing this hook can do with an error, and it turns
				// every upstream-side problem — refused, unreachable, cleartext
				// where TLS was expected, a certificate that does not check out
				// — into one opaque `tls: internal error`, which no retry-on-5xx
				// and no circuit breaker can act on. Terminating and letting the
				// request path answer 502 says what actually happened, and is
				// what the same outage on a cleartext route already did.
				return nil, nil
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
		// No upstream to mirror, so the client's own order is what there is to
		// go on. Answering from a fixed list instead gave h2 to a client that
		// had asked for http/1.1 first and left it no way to say otherwise.
		cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			narrowed := httpALPN(hello.SupportedProtos)
			if len(narrowed) == 0 {
				// Nothing this proxy can carry, or no ALPN at all. The base
				// list stands: a client that offered nothing must still be
				// answered with something it can use.
				return nil, nil
			}
			c := base.Clone()
			c.NextProtos = narrowed
			return c, nil
		}
	}

	// The peek deadline was cleared once the tunnel kind was decided, so the
	// handshake needs its own: it reads the rest of the ClientHello, and a peer
	// that stops mid-record would otherwise block here indefinitely. Cleared
	// again below so it cannot cut short the traffic that follows.
	clientConn.SetDeadline(time.Now().Add(mitmHandshakeTimeout.Get()))

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

// maxPendingUpstreamDials caps how many upstream connections may be open on
// behalf of client handshakes that have not completed. A variable so tests need
// not open hundreds of connections to reach it.
var maxPendingUpstreamDials = 64

// acquirePreDial takes a slot for an upstream dial made during a client
// handshake, reporting false when there is none to take.
func (p *MITMProxy) acquirePreDial() (release func(), ok bool) {
	p.preDialOnce.Do(func() {
		p.preDial = make(chan struct{}, maxPendingUpstreamDials)
	})
	select {
	case p.preDial <- struct{}{}:
		return func() { <-p.preDial }, true
	default:
		return nil, false
	}
}

// sessionTicketKeyLifetime is how long one key is used to issue new session
// tickets, and sessionTicketKeysKept how many older ones stay around to decrypt
// tickets already handed out. The same shape Go uses when it manages the keys
// itself, which taking them over here would otherwise have turned off: one key
// for the life of the process means a ticket recorded today is decryptable by
// anyone who obtains that key tomorrow.
const (
	sessionTicketKeyLifetime = 8 * time.Hour
	sessionTicketKeysKept    = 3
)

// tlsBase is the one server config every intercepted connection is cloned from.
//
// It exists so session ticket keys have somewhere to live. Go stores them on
// the Config and initialises them on first use, so a config built fresh per
// connection issued tickets nobody could ever redeem: every client fell back to
// a full handshake, every time. The keys are set explicitly rather than left to
// that first use, because a clone taken before it would get its own.
//
// Rotating the parent does not disturb clones already in flight — each carries
// the keys it was cloned with — and a new clone still holds the older keys, so
// a ticket issued before a rotation is honoured until it ages out.
func (p *MITMProxy) tlsBase() *tls.Config {
	p.tlsBaseMu.Lock()
	defer p.tlsBaseMu.Unlock()

	if p.tlsBaseCfg == nil {
		p.tlsBaseCfg = &tls.Config{
			// Every clone inherits this, so the client half of every
			// intercepted session is covered by one assignment.
			KeyLogWriter: tlsKeyLogWriter(),
			// The floor ALPN selection starts from. An upstream that negotiates
			// nothing leaves nothing to mirror, and without this the proxy would
			// answer ServerHello with no ALPN extension — which a client that
			// requires one, gRPC among them, cannot use.
			NextProtos: []string{"h2", "http/1.1"},
		}
	}

	if time.Since(p.ticketKeysAt) >= sessionTicketKeyLifetime {
		var key [32]byte
		if _, err := rand.Read(key[:]); err == nil {
			p.ticketKeys = append([][32]byte{key}, p.ticketKeys...)
			if len(p.ticketKeys) > sessionTicketKeysKept {
				p.ticketKeys = p.ticketKeys[:sessionTicketKeysKept]
			}
			p.tlsBaseCfg.SetSessionTicketKeys(p.ticketKeys)
			p.ticketKeysAt = time.Now()
		}
	}
	return p.tlsBaseCfg
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

// probeH2C reports whether target speaks cleartext HTTP/2, asking it once.
//
// The answer is shared between everyone who wants it at the same time. A probe
// costs a dial and a wait for the peer's SETTINGS — up to eight seconds, on the
// request path, across the whole tunnel — and a burst of requests for a target
// nobody has probed yet used to run one each, every one of them blocking its
// own request to learn the same fact.
func (p *MITMProxy) probeH2C(target string) bool {
	return p.h2cProbes.do(target, func() (bool, bool) { return p.dialProbeH2C(target) })
}

// probe is one probe in progress; answer is written before done is closed, so
// everyone waiting on it sees the finished value.
type probe struct {
	done   chan struct{}
	answer bool
}

// probeCache remembers what was learned about an upstream by asking it, and
// lets only one question at a time be asked of the same one: a probe costs a
// dial across the whole tunnel, and a burst of requests for an unprobed target
// used to run one each, every one of them blocking its own request to learn the
// same fact.
type probeCache struct {
	answers  sync.Map // target → probeAnswer
	mu       sync.Mutex
	inflight map[string]*probe
}

// probeAnswer is a remembered answer and when it was learned.
type probeAnswer struct {
	value bool
	at    time.Time
}

// probeTTL is how long an answer about an upstream is trusted. What was learned
// was learned about an upstream as it was: a backend keeps its address across a
// redeploy that adds or drops h2c, or that puts TLS in front of it, so an answer
// with no expiry pins it to the wrong protocol until the process restarts.
// noMITM expires its own for exactly this reason. A variable so tests need not
// wait it out.
var probeTTL = 10 * time.Minute

// known reports whether an unexpired answer has been remembered for target.
func (c *probeCache) known(target string) bool {
	_, ok := c.remembered(target)
	return ok
}

func (c *probeCache) remembered(target string) (bool, bool) {
	v, ok := c.answers.Load(target)
	if !ok {
		return false, false
	}
	answer := v.(probeAnswer)
	if time.Since(answer.at) > probeTTL {
		c.answers.CompareAndDelete(target, v)
		return false, false
	}
	return answer.value, true
}

// do returns what is known about target, running ask once if nothing is. ask
// reports the answer and whether it is worth remembering — a transient failure
// says nothing about the peer, and pinning one would outlive its cause.
func (c *probeCache) do(target string, ask func() (answer, remember bool)) bool {
	if answer, ok := c.remembered(target); ok {
		return answer
	}

	c.mu.Lock()
	if inflight, ok := c.inflight[target]; ok {
		c.mu.Unlock()
		<-inflight.done
		return inflight.answer
	}
	// Re-read under the lock: the probe this call would have joined may have
	// finished and published between the Load above and here.
	if answer, ok := c.remembered(target); ok {
		c.mu.Unlock()
		return answer
	}
	inflight := &probe{done: make(chan struct{})}
	if c.inflight == nil {
		c.inflight = make(map[string]*probe)
	}
	c.inflight[target] = inflight
	c.mu.Unlock()

	answer, remember := ask()
	inflight.answer = answer
	if remember {
		c.answers.Store(target, probeAnswer{value: answer, at: time.Now()})
	}

	c.mu.Lock()
	delete(c.inflight, target)
	c.mu.Unlock()
	close(inflight.done)

	return answer
}

func (p *MITMProxy) dialProbeH2C(target string) (h2c, remember bool) {
	// The dial and round-trip travel the whole tunnel (server -> SSH -> client
	// -> upstream), so a transient failure — tunnel reconnecting, slow hop —
	// says nothing about whether the target speaks h2c. Cache only a
	// deterministic answer; leave transient failures unmemoized so the next
	// request re-probes instead of pinning the target to HTTP/1.1 forever.
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return false, false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	// HTTP/2 connection preface
	if _, err := conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		return false, false
	}
	buf := make([]byte, 9) // h2 frame header
	if _, err := io.ReadFull(conn, buf); err != nil {
		return false, false
	}
	return buf[3] == 0x04, true // SETTINGS frame type
}

// upstreamTLSName decides how to reach a target whose scheme nobody stated,
// for a route that carries a credential. It returns the name to present as SNI,
// or "" when the upstream is confirmed to speak cleartext.
//
// The credential is never written speculatively. Reading TLS off the port
// number — the only signal there used to be, and only for 443 — sent it to an
// HTTPS backend on 8443 as plaintext, on the first attempt and on every retry,
// with nothing but a 502 to show for it. A ClientHello gives away nothing, so
// asking is safe where guessing is not.
func (p *MITMProxy) upstreamTLSName(target string) (string, error) {
	answered := false
	speaksTLS := p.tlsProbes.do(target, func() (bool, bool) {
		tls, remember := dialProbeTLS(target)
		answered = remember
		return tls, remember
	})
	if !speaksTLS {
		if !answered && !p.tlsProbes.known(target) {
			// Neither a handshake nor a refusal: the upstream said nothing to
			// a ClientHello. Cleartext is a guess, and the thing being guessed
			// about is whether to put a credential on the wire unencrypted.
			return "", fmt.Errorf("upstream %s did not answer either way when asked whether it speaks TLS; "+
				"write tls://%s or http://%s to say which it is", target, target, target)
		}
		return "", nil
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return "", fmt.Errorf("upstream %s speaks TLS but is not a host:port", target)
	}
	if net.ParseIP(host) != nil {
		// An IP is not a name: Go will not send it as SNI and cannot verify a
		// certificate against it, so there is no honest way to open TLS here.
		return "", fmt.Errorf("upstream %s speaks TLS but was configured by address and without a scheme; "+
			"write tls://%s together with WithSNI(<the name its certificate is issued for>)", target, target)
	}
	return host, nil
}

// upstreamProbeTimeout bounds the question "does this speak TLS". It is short
// on purpose: an answer either way arrives in one round trip, and anything
// slower is not an answer but a hang.
const upstreamProbeTimeout = 2 * time.Second

func dialProbeTLS(target string) (speaksTLS, remember bool) {
	conn, err := net.DialTimeout("tcp", target, upstreamProbeTimeout)
	if err != nil {
		return false, false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(upstreamProbeTimeout))

	// Only the question "does a handshake complete at all" is being asked here;
	// whether the certificate checks out is the real connection's business.
	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // not a trust decision
	if err := tc.Handshake(); err != nil {
		// A cleartext server answers a ClientHello with an error, a plain HTTP
		// response or a close, none of which look like a handshake. Any of them
		// is a deterministic "not TLS"; only never getting there is not.
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return false, false
		}
		return false, true
	}
	return true, true
}

// refusingTransport answers every request with the same configuration error,
// so a route the proxy cannot honestly serve fails as a 502 that names the fix
// instead of putting the credential on the wire to find out.
type refusingTransport struct{ err error }

func (t refusingTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, t.err }

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
	// Registered before the handler is built, not after. Building one can take
	// real time — the h2c probe of a new target is a dial and a wait, on this
	// very path — and a Shutdown landing in that window would not know this
	// session existed, leaving it to be cut off at the deadline instead of
	// drained.
	h1srv := &http.Server{
		ReadHeaderTimeout: serverReadHeaderTimeout.Get(),
		// See the proxy listener: an intercepting proxy forwards `OPTIONS *`
		// rather than answering it.
		DisableGeneralOptionsHandler: true,
	}
	h2srv := &http2.Server{}
	if err := http2.ConfigureServer(h1srv, h2srv); err != nil {
		log.Printf("[vtunnel-proxy] MITM %s: configure HTTP/2 server: %v", authority, err)
		return
	}
	defer p.trackNested(h1srv)()

	handler, release := p.routeHandler(authority, rt, up, true, true)
	defer release()

	// Building that handler can take a while — probing an unknown target for
	// h2c is a dial and a wait — and a Shutdown that ran meanwhile has already
	// been round every nested server there was. Starting to serve now would
	// produce a session nothing will ever tell to go away: Shutdown would sit
	// out its whole deadline and then cut it off. Refusing the connection is
	// what every other request arriving after Shutdown already gets.
	if p.closed() {
		log.Printf("[vtunnel-proxy] MITM %s: shutting down, not serving this session", authority)
		return
	}

	h2srv.ServeConn(clientConn, &http2.ServeConnOpts{
		BaseConfig: h1srv,
		Handler:    handler,
	})
}

// routeHandler turns a route into the handler that serves it: the caller's own
// handler for an in-process route, or a reverse proxy to its target. Both are
// wrapped in the configured middleware, so a Use hook sees every request the
// proxy terminates regardless of where it ends up.
// reresolve tells routeHandler whether to look the route up again for every
// request. Inside a CONNECT tunnel it must: the connection outlives any number
// of configuration changes, and the sandbox decides how long. The cleartext
// entry point passes false because it has already resolved this request itself
// — and because what it hands over may be a synthesised route for a domain
// nobody mapped, which a second lookup would not find.
func (p *MITMProxy) routeHandler(authority string, rt route, up *upstreamTLSConn, preferH2, reresolve bool) (http.Handler, func()) {
	// Built once for the route the CONNECT resolved to, which is the one almost
	// every request on this connection will also resolve to. The pre-dialled
	// upstream belongs to it, so this pair is the only one that may use it.
	connectHandlers, release := p.buildRouteHandlers(authority, rt, up, preferH2)

	// Whatever revision this connection ends up serving after a config change.
	// Only the newest is kept: a connection follows the route table, and the
	// table has one answer at a time.
	var rebuilt revisionCache

	// The route — and with it the target and the credential — was chosen from
	// the authority this connection was opened for. Every request inside it
	// carried its own Host, so a sandbox could open one CONNECT to a domain it
	// is allowed to reach and then aim the injected credential at any other
	// virtual host that upstream serves. RFC 9110 §7.2 requires the two to
	// agree, and 421 is the answer for when they do not.
	expectHost := hostFromAuthority(authority)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The route is read again for every request, not captured with the
		// connection. A tunnel is long-lived — an h2 session or an HTTP/1.1
		// keep-alive lasts as long as the sandbox chooses to hold it — so a
		// route captured at CONNECT time is one the sandbox can pin: a rotated
		// credential kept being injected, a repointed domain kept reaching the
		// old backend, and a withdrawn one kept being served, all of them
		// looking correct from the route table's side. The cleartext path
		// always did this; only the CONNECT path did not.
		current, routed := rt, true
		if reresolve {
			current, routed = p.resolveDomain(authority)
			if routed && current.target == "" && current.handler == nil {
				// The table holds a route with no target of its own; the
				// connection was set up with that filled in from the authority,
				// and re-reading it lost that. Put it back, on the same terms —
				// including the upstream scheme this connection settled on,
				// since a route like this follows its client.
				current.target, current.selfTarget = authority, true
				current.tlsHost = rt.tlsHost
			}
		}
		if !routed {
			if unmapped := p.unmappedHandler(); unmapped != nil {
				unmapped.ServeHTTP(w, r)
				return
			}
			log.Printf("[vtunnel-proxy] %s %s: the route was withdrawn while this connection was open", r.Method, authority)
			http.Error(w, "vtunnel: domain not allowed", http.StatusForbidden)
			return
		}

		handlers := connectHandlers
		if current.generation != rt.generation {
			// Something about this route changed under the open connection. The
			// pre-dialled upstream was negotiated for the old revision, so it
			// is not offered to the new one: dial afresh. Kept for as long as
			// the revision lasts rather than rebuilt per request — a connection
			// that outlives one config change would otherwise pay for it on
			// every request it has left.
			handlers = rebuilt.get(current.generation, func() (routeHandlers, func()) {
				return p.buildRouteHandlers(authority, current, nil, preferH2)
			})
		}

		// Read per request too, so a middleware registered after the connection
		// opened applies to it.
		p.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p.serveRouted(w, r, handlers, current.headers, expectHost, authority, preferH2)
		})).ServeHTTP(w, r)
	}), func() { release(); rebuilt.close() }
}

// revisionCache holds the handlers built for one revision of a route, so a
// long-lived connection rebuilds them when the route changes rather than for
// every request after it. Requests on an h2 session arrive concurrently, hence
// the lock.
type revisionCache struct {
	mu         sync.Mutex
	generation uint64
	handlers   routeHandlers
	release    func()
	built      bool
}

func (c *revisionCache) get(generation uint64, build func() (routeHandlers, func())) routeHandlers {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.built && c.generation == generation {
		return c.handlers
	}
	c.releaseLocked()
	c.handlers, c.release = build()
	c.generation = generation
	c.built = true
	return c.handlers
}

// close releases whatever the last revision held. Called when the connection
// ends, alongside the release for the route it opened with.
func (c *revisionCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.releaseLocked()
	c.built = false
}

func (c *revisionCache) releaseLocked() {
	if c.release != nil {
		c.release()
		c.release = nil
	}
}

// routeHandlers is the pair of handlers a route resolves to: the ordinary one,
// and the one that takes over the connection for a protocol upgrade.
type routeHandlers struct {
	serve   http.Handler
	upgrade http.Handler
}

func (p *MITMProxy) buildRouteHandlers(authority string, rt route, up *upstreamTLSConn, preferH2 bool) (routeHandlers, func()) {
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
	return routeHandlers{serve: h, upgrade: upgrade}, release
}

func (p *MITMProxy) serveRouted(w http.ResponseWriter, r *http.Request, handlers routeHandlers, inject http.Header, expectHost, authority string, preferH2 bool) {
	r.RequestURI = ""

	// HTTP/1.0 has no Host header, and net/http hands such a request to the
	// handler as it stands (it answers 400 itself for HTTP/1.1). An empty
	// Host is not a different host — it is no claim at all — so the
	// authority this connection was opened for is filled in. Nothing is
	// widened by that: it is the very value the comparison below would have
	// demanded.
	if r.Host == "" && expectHost != "" {
		r.Host = authority
		if r.URL != nil {
			r.URL.Host = authority
		}
	}

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
		removeClaimedOrigin(r.Header)
		injectConfiguredHeaders(r, inject)
		handlers.upgrade.ServeHTTP(w, r)
		return
	}

	removeHopByHop(r.Header, true)
	removeClaimedOrigin(r.Header)
	injectConfiguredHeaders(r, inject)
	handlers.serve.ServeHTTP(w, r)
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

		// An informational response is an answer that arrives before the
		// answer: 103 Early Hints tells a client what to start fetching while
		// the upstream is still working. RoundTrip does not surface them at
		// all, so they were dropped here — the same plumbing net/http's own
		// reverse proxy uses is what gets them out.
		var (
			roundTripMu   sync.Mutex
			roundTripDone bool
		)
		r = r.WithContext(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{
			Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
				// 100 Continue is not passed on. It answers an expectation the
				// client made of whoever reads its body, and net/http answers
				// that itself the moment this handler's transport starts
				// reading — forwarding the upstream's answer to the same
				// question gave the client two of them.
				if code == http.StatusContinue {
					return nil
				}

				roundTripMu.Lock()
				defer roundTripMu.Unlock()
				if roundTripDone {
					// The response is already being written; the header map is
					// no longer ours to touch.
					return nil
				}

				// The hint's headers belong to the hint: left in place they
				// would be written again as part of the real response. Only
				// they go, though. Clearing the whole map took the response
				// headers a Use middleware had already set with them, so a
				// stamp that was on every answer vanished from all of them the
				// day an upstream started sending 103.
				h := w.Header()
				restore := make(map[string][]string, len(header))
				for k := range header {
					k = textproto.CanonicalMIMEHeaderKey(k)
					if _, seen := restore[k]; !seen {
						restore[k] = h[k]
					}
				}
				for k, vv := range header {
					for _, v := range vv {
						h.Add(k, v)
					}
				}
				w.WriteHeader(code)
				for k, before := range restore {
					if before == nil {
						delete(h, k)
						continue
					}
					h[k] = before
				}
				return nil
			},
		}))

		// An HTTP/2 server hands its handler a non-nil body even for a request
		// that ended on its HEADERS frame, where net/http's HTTP/1 server uses
		// http.NoBody. Re-issued as it stands, such a request has an outgoing
		// length net/http reads as unknown: chunked framing to an HTTP/1
		// upstream, an extra empty DATA frame to an HTTP/2 one, and — because a
		// request with an unknown body is not replayable — no retry when a
		// pooled connection turns out to have been closed at the other end. An
		// h1 client survived that race and an h2 client got a 502.
		if r.ContentLength == 0 {
			r.Body = nil
		}

		resp, err := transport.RoundTrip(r)
		roundTripMu.Lock()
		roundTripDone = true
		roundTripMu.Unlock()
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

		// A 101 answers a request that asked to switch protocols, and such a
		// request never reaches here — isUpgradeRequest sends it down the splice
		// path instead. So this one was not asked for, and there is nothing on
		// this path that can act on it: the hop-by-hop sweep strips the very
		// headers that say what was switched to, net/http refuses to write a
		// body for a 101, and the upstream's bytes after it are dropped. The
		// client used to be handed a bare 101 and a connection that then said
		// nothing ever again.
		if resp.StatusCode == http.StatusSwitchingProtocols {
			log.Printf("[vtunnel-proxy] %s %s -> %s: upstream switched protocols without being asked to; refusing",
				r.Method, authority, target)
			http.Error(w, "vtunnel: upstream switched protocols unexpectedly", http.StatusBadGateway)
			return
		}

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

	if rt.h2c {
		// Stated, so there is nothing to probe and nothing to infer from what
		// the client happened to negotiate. This is also the only way to reach
		// an h2c-only upstream from an HTTP/1.1 client: the probe below is asked
		// only when the client side is HTTP/2 too.
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

	tlsHost := rt.tlsHost
	if tlsHost == "" && len(rt.headers) > 0 && !rt.cleartext {
		// Nobody said how to reach this upstream, and this route carries a
		// credential. Ask before writing it.
		name, err := p.upstreamTLSName(target)
		if err != nil {
			return refusingTransport{err}, "https", noRelease
		}
		tlsHost = name
	}

	if tlsHost != "" {
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
	handler, release := p.routeHandler(authority, rt, up, false, true)
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
		ReadHeaderTimeout: serverReadHeaderTimeout.Get(),
		// See the proxy listener: an intercepting proxy forwards `OPTIONS *`
		// rather than answering it.
		DisableGeneralOptionsHandler: true,
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

// CloseWrite forwards half-close, for the same reason bufferedConn does: an
// embedded net.Conn answers dualStream's assertion for the interface, not for
// the *tls.Conn behind it, so without this every half-close inside an
// intercepted HTTP/1 session became a full close and the peer lost the rest of
// the response it was still streaming.
func (c *notifyConn) CloseWrite() error {
	cw, ok := c.Conn.(closeWriter)
	if !ok {
		return fmt.Errorf("half-close unsupported by %T", c.Conn)
	}
	return cw.CloseWrite()
}

// schemeTLSHost reads the protocol the client asked for out of an absolute-form
// URL, for a request going to the host it named rather than to a configured
// target.
//
// `GET https://host/path` at a proxy port is unusual — a client that wants TLS
// normally sends CONNECT — but it is legal, and the scheme is the client saying
// what to speak to the origin. Taking the route's word for it and not the URL's
// sent such a request to port 443 in the clear, with whatever credential the
// client had attached to a request it believed it had asked to encrypt.
func schemeTLSHost(r *http.Request, hostPort string) string {
	if r.URL == nil || r.URL.Scheme != "https" {
		return ""
	}
	return hostFromAuthority(hostPort)
}

func (p *MITMProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// A request with no Host names no destination. Synthesising one produced
	// ":80" — a perfectly dialable address in Go, meaning the local machine —
	// so a request nobody could route became a connection to this host's own
	// loopback. Inside a CONNECT the authority is known and routeHandler fills
	// it in; here there is nothing to fill it in from.
	if r.Host == "" && r.URL.Host == "" {
		w.Header().Set("Connection", "close")
		http.Error(w, "vtunnel: request has no Host header, destination unknown", http.StatusBadRequest)
		return
	}

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

	// A cleartext HTTP/2 request stays one. The listener speaks h2c precisely so
	// a gRPC client can be pointed straight at this proxy with no CONNECT in
	// front, and flattening every request to HTTP/1.1 threw that away twice
	// over: the upstream was re-dialled as HTTP/1.1, and TE: trailers went with
	// the hop-by-hop sweep — which is the header a gRPC call needs to get its
	// status back.
	keepH2 := r.ProtoMajor == 2
	if !keepH2 {
		r.Proto = "HTTP/1.1"
		r.ProtoMajor = 1
		r.ProtoMinor = 1
	}

	rt, isRouted := p.resolveDomain(hostPort)
	switch {
	case !isRouted:
		if unmapped := p.unmappedHandler(); unmapped != nil {
			log.Printf("[vtunnel-proxy] %s %s: no route", r.Method, hostPort)
			p.wrap(unmapped).ServeHTTP(w, r)
			return
		}
		// Nothing routed and nothing to refuse with: send it where it asked to go.
		rt = route{target: hostPort, tlsHost: schemeTLSHost(r, hostPort)}
	case rt.target == "" && rt.handler == nil:
		// A Forward route names no target of its own, so it means "go to the
		// host you asked for" — here as on the CONNECT path.
		rt.target, rt.selfTarget = hostPort, true
	}
	// An absolute-form "GET https://…" is this path's equivalent of a TLS
	// tunnel, and the only thing here a route can follow.
	rt = rt.followClientScheme(r.URL != nil && r.URL.Scheme == "https")

	if rt.handler == nil {
		log.Printf("[vtunnel-proxy] %s %s %s -> %s", r.URL.Scheme, r.Method, hostPort, rt.target)
	} else {
		log.Printf("[vtunnel-proxy] %s %s %s -> handled in process", r.URL.Scheme, r.Method, hostPort)
	}
	handler, release := p.routeHandler(hostPort, rt, nil, keepH2, false)
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

// raceForFirstBytes dials the upstream and waits for whichever side speaks
// first, so a tunnel whose client is silent is decided by evidence rather than
// by a timeout.
//
// It returns the dialled connection either way, greeting and all, so the pipe
// that follows does not open a second one — and reports whether the upstream is
// what spoke, which is the only thing here that proves anything.
//
// The two waiters each own one side, and the loser is stopped before its side
// is touched again: a deadline in the past unblocks the peek, and bufio keeps
// what it buffered and forgets the timeout.
func (p *MITMProxy) raceForFirstBytes(rawConn net.Conn, br *bufio.Reader, target string, deadline time.Time) (up *bufferedConn, greeted bool) {
	release, ok := p.acquirePreDial()
	if !ok {
		return nil, false
	}
	defer release()

	conn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		log.Printf("[vtunnel-proxy] dial %s failed: %v", target, err)
		return nil, false
	}
	conn.SetReadDeadline(deadline)
	upBr := bufio.NewReader(conn)

	spoke := make(chan bool, 2) // true: the upstream, false: the client
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		upBr.Peek(1)
		spoke <- true
	}()
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		rawConn.SetReadDeadline(deadline)
		br.Peek(1)
		spoke <- false
	}()

	upstreamFirst := <-spoke

	// Stop both waiters before their sides are read again.
	conn.SetReadDeadline(time.Now())
	rawConn.SetReadDeadline(time.Now())
	<-upstreamDone
	<-clientDone
	conn.SetReadDeadline(time.Time{})

	if upstreamFirst && upBr.Buffered() == 0 {
		// The upstream returned without saying anything — it hung up, or the
		// deadline arrived. Not a greeting.
		upstreamFirst = false
	}
	return newBufferedConn(conn, upBr), upstreamFirst
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

// tunnelKind is what the bytes inside a CONNECT tunnel turn out to be.
type tunnelKind int

const (
	// tunnelOpaque is anything this proxy does not terminate: a protocol it
	// does not speak, or a client that is waiting for the server to speak
	// first and has therefore said nothing to go on.
	tunnelOpaque tunnelKind = iota
	tunnelTLS
	tunnelH2C
	tunnelHTTP1
)

// classifyTunnel decides what a CONNECT tunnel carries from its opening bytes.
//
// The hard part is not recognising each protocol, it is knowing when to stop
// waiting. Deciding from one read misreads a request line that TCP split across
// two segments — and the sandbox egress proxy's tunnel hop re-segments everything it
// carries, so the same client, sending the same bytes, was injected into on one
// connection and piped on the next. Waiting for a whole line instead hangs every
// protocol whose server greets first, which says nothing at all until it is
// greeted.
//
// So the buffer grows only while what has arrived could still become something
// this proxy terminates, and the decision is made the moment it could not.
// Anything binary settles it on the first byte; a redis inline command settles
// it at its first line ending; a request line split down the middle is waited
// for, because it is still a viable request line.
func classifyTunnel(br *bufio.Reader) tunnelKind {
	for {
		head, _ := br.Peek(min(max(br.Buffered(), 1), maxRequestLinePeek))
		if len(head) == 0 {
			return tunnelOpaque
		}
		if startsLikeTLSRecord(head) {
			return tunnelTLS
		}
		if isH2CPreface(br) {
			return tunnelH2C
		}
		if line, ok := firstLine(head); ok {
			// The whole line is required, version and all, rather than a
			// method-looking word: "GET key\r\n" is a valid redis inline
			// command, and mistaking one for HTTP would mean parsing a
			// connection that should have been piped.
			return classifyRequestLine(line)
		}
		if len(head) >= maxRequestLinePeek || !viableTunnelPrefix(head) {
			return tunnelOpaque
		}
		if _, err := br.Peek(len(head) + 1); err != nil {
			return tunnelOpaque
		}
	}
}

func classifyRequestLine(line []byte) tunnelKind {
	if couldBeRequestLine(line) && bytes.LastIndex(line, []byte(" HTTP/1.")) > 0 {
		return tunnelHTTP1
	}
	return tunnelOpaque
}

// couldBeRequestLine reports whether b is a request line, or the start of one.
// Everything that asks the question asks it here — two nearly-identical rules
// is what the fuzzer found first, twice: one accepted a one-letter method where
// the other demanded three, and one tolerated a byte outside printable ASCII
// where the other did not. Either way the same bytes were read differently
// depending on where TCP split them.
func couldBeRequestLine(b []byte) bool {
	return requestLinePrefix(b) && printableASCII(b)
}

// maxMethodLen is how long a method token may be before this stops reading like
// a request line. Longer than any method anyone registered — PROPPATCH is nine
// — with room to spare, because being generous here costs a bounded wait and
// being strict costs a misclassification.
const maxMethodLen = 16

// requestLinePrefix reports whether b opens with a method token, whole or still
// arriving.
func requestLinePrefix(b []byte) bool {
	space := bytes.IndexByte(b, ' ')
	if space < 0 {
		return len(b) <= maxMethodLen && isUpperASCII(b)
	}
	return space >= 1 && space <= maxMethodLen && isUpperASCII(b[:space])
}

func isUpperASCII(b []byte) bool {
	for _, c := range b {
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
}

// firstLine splits off the first line of head, if all of it has arrived. A bare
// LF ends it: RFC 9112 §2.2 lets a recipient accept one, net/http's own parser
// does, and refusing it here made the sniffer stricter than the parser behind
// it — so a request that would have been served and injected into was piped
// through instead.
func firstLine(head []byte) ([]byte, bool) {
	line, _, ok := bytes.Cut(head, []byte("\n"))
	if !ok {
		return nil, false
	}
	return bytes.TrimSuffix(line, []byte("\r")), true
}

// viableTunnelPrefix reports whether head, which is not yet a decision, could
// still grow into one. Everything else is opaque right now rather than after a
// wait nobody is going to satisfy.
func viableTunnelPrefix(head []byte) bool {
	if head[0] == tlsHandshakeRecordType {
		// A TLS record header still arriving. Two clients out of three send all
		// five bytes at once, but a prefix is not evidence against.
		return len(head) < tlsRecordHeaderLen && (len(head) < 2 || head[1] == 0x03)
	}
	// A request line still arriving, whose ending has not come yet.
	return couldBeRequestLine(head)
}

func printableASCII(b []byte) bool {
	for _, c := range b {
		if (c < 0x20 || c > 0x7e) && c != '\r' && c != '\t' {
			return false
		}
	}
	return true
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// maxRequestLinePeek bounds how much of a first line is examined, and is the
// size the tunnel's reader is given so that the bound is the real one: a peek
// past the end of a bufio buffer fails rather than growing it, so a smaller
// buffer would have capped the classification somewhere this constant does not
// mention. A request line longer than this is one net/http would refuse anyway.
const maxRequestLinePeek = 8 << 10

// isH2CPreface reports whether the connection opens with the HTTP/2 client
// preface.
//
// The prefix is checked against what is already buffered before asking for the
// whole 24 bytes, because a peek waits for them. Every protocol that opens with
// a short packet and then expects the server to speak first — postgres sends
// eight bytes, redis six — used to sit here until the peek timeout expired
// before a single byte was forwarded. An h2c client, by contrast, sends the
// whole preface at once, so waiting for the rest only happens when the rest is
// already on its way.
func isH2CPreface(br *bufio.Reader) bool {
	head, _ := br.Peek(min(br.Buffered(), len(http2.ClientPreface)))
	if len(head) == 0 || !strings.HasPrefix(http2.ClientPreface, string(head)) {
		return false
	}
	full, err := br.Peek(len(http2.ClientPreface))
	if err != nil {
		return false
	}
	return string(full) == http2.ClientPreface
}

// portFromAuthority reads the port half of an authority. Every authority a
// route is resolved from has been through isRoutableAuthority, which refuses
// one without a port, so the empty answer is unreachable rather than a default
// worth picking.
func portFromAuthority(authority string) string {
	_, port, err := net.SplitHostPort(authority)
	if err != nil {
		return ""
	}
	return port
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
