package vtunnel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/vivid-money/vtunnel/internal/proxy"
	"github.com/vivid-money/vtunnel/internal/proxy/socks5"
)

// EgressProxy is the sandbox-side forward proxy. It is deliberately dumb: it holds
// an allowlist of domains and nothing else — no CA, no credentials, no TLS
// termination.
//
// The domain comes from the CONNECT request line, which the application sends
// in cleartext before any TLS, so routing needs no decryption. Allowlisted
// requests are chained to the controlplane's proxy through a tunnel port,
// exactly like any HTTP proxy chaining to an upstream proxy; everything else is
// dialed directly, so unmapped traffic still egresses from the sandbox.
type EgressProxy struct {
	// routes maps a domain pattern to the tunnel port that reaches the
	// controlplane proxy responsible for it.
	routes map[string]int
	mu     sync.RWMutex

	transport http.Transport
	// chained holds one transport per tunnel port. Cloning per request looked
	// harmless but leaked: the clone inherits a zero IdleConnTimeout, goes out
	// of scope right after RoundTrip with nobody to call CloseIdleConnections,
	// and its idle connection plus read and write goroutines then live until
	// the process exits. Keep-alive never worked either — every request opened
	// a fresh connection.
	chained   map[int]*http.Transport
	chainedMu sync.Mutex

	// lifecycleMu guards what Start installs; Addr and Close read it from other
	// goroutines.
	//
	// stopped is a flag rather than a sync.Once because Close is documented as
	// safe before Start: spending a once there left the guard disarmed for the
	// listener installed afterwards, which nothing could then close. The proxy
	// carries the same flag, added after the same bug.
	lifecycleMu sync.Mutex
	listener    net.Listener
	srv         *http.Server
	stopped     bool

	// detached holds the connections net/http stops managing the moment they
	// are hijacked, plus every SOCKS5 connection, which never reaches net/http
	// at all. Between them that is nearly everything the egress proxy carries, and
	// without a registry Close could not reach any of it.
	detachedMu sync.Mutex
	detached   map[io.Closer]struct{}

	// policy decides what may be reached without crossing the tunnel. Nil means
	// none was ever set, which is not the same as an empty one: nil is the
	// behaviour this proxy has always had, where anything unrouted is dialled.
	//
	// Atomic rather than mutex-guarded because it is read on the dial path of
	// every connection, including from inside net/http's own dialer, where
	// taking a lock the rest of this type also takes would be one deadlock away.
	policy atomic.Pointer[compiledPolicy]
}

// SetPolicy installs the rules deciding what this sandbox may reach directly.
// A nil policy removes them, restoring the behaviour of a proxy that was never
// given any: routed domains cross the tunnel and everything else is dialled.
//
// It is safe to call at any time, and calling it with rules that are already in
// force does nothing at all — see the fingerprint on compiledPolicy. That
// matters because the controlplane replays its policy on every reconnect, and a
// sandbox on a flapping link would otherwise drop its whole cleartext
// connection pool once per flap.
//
// Connections already established are not reconsidered. A CONNECT tunnel or a
// SOCKS5 stream is a byte pipe with no request boundary to stop at, and tearing
// them down here would kill every live one on every reconnect; [EgressProxy.Close]
// is what ends those. Idle pooled connections are dropped, because a pool hit
// never reaches the dialler and would otherwise serve a destination the new
// rules refuse.
func (r *EgressProxy) SetPolicy(p *Policy) error {
	if p == nil {
		if old := r.policy.Swap(nil); old != nil {
			log.Printf("[vtunnel-egress] Egress policy removed; unrouted destinations are dialled again")
			r.transport.CloseIdleConnections()
		}
		return nil
	}

	compiled, err := p.compile()
	if err != nil {
		return err
	}
	if old := r.policy.Load(); old != nil && old.fingerprint == compiled.fingerprint {
		return nil
	}
	r.policy.Store(compiled)
	r.transport.CloseIdleConnections()

	log.Printf("[vtunnel-egress] Egress policy: default %s, %d allow, %d deny",
		compiled.def, len(p.Allow), len(p.Deny))
	r.warnRoutesContradictingPolicy(compiled)
	return nil
}

// warnRoutesContradictingPolicy says so when a route names a domain the policy
// denies. The route wins — it does not egress from the sandbox at all — but an
// operator who wrote that deny meant something by it, and finding out from the
// traffic is the wrong way round.
func (r *EgressProxy) warnRoutesContradictingPolicy(policy *compiledPolicy) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for domain := range r.routes {
		// splitRule, not net.SplitHostPort: a route covering every port is
		// written without one, and reading that as a parse failure skipped the
		// warning for exactly the shape most likely to contradict a rule.
		host, port, err := splitRule(domain)
		if err != nil {
			continue
		}
		if policy.matchName(host, port) == verdictDeny {
			log.Printf("[vtunnel-egress] WARNING: %s is denied by the egress policy and also routed "+
				"through the tunnel; the route wins, because the controlplane dials it and this "+
				"sandbox does not", domain)
		}
	}
}

// track registers a connection Close must be able to reach, and returns the
// function that forgets it again.
func (r *EgressProxy) track(c io.Closer) func() {
	r.detachedMu.Lock()
	if r.detached == nil {
		r.detached = make(map[io.Closer]struct{})
	}
	r.detached[c] = struct{}{}
	r.detachedMu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			r.detachedMu.Lock()
			delete(r.detached, c)
			r.detachedMu.Unlock()
		})
	}
}

// closeDetached drops every tracked connection. The map is emptied first so the
// untrack functions still running have nothing left to find.
func (r *EgressProxy) closeDetached() {
	r.detachedMu.Lock()
	conns := make([]io.Closer, 0, len(r.detached))
	for c := range r.detached {
		conns = append(conns, c)
	}
	clear(r.detached)
	r.detachedMu.Unlock()

	for _, c := range conns {
		c.Close()
	}
}

// connectReplyTimeout bounds the wait for a chained proxy to answer a CONNECT.
// A variable rather than a constant so tests need not wait it out.
var connectReplyTimeout = dialTimeout

func newEgressProxy() *EgressProxy {
	r := &EgressProxy{
		routes:  make(map[string]int),
		chained: make(map[int]*http.Transport),
	}
	// The same bounds the proxy's transport carries, and for the same reasons:
	// a zero http.Transport dials with no timeout at all and keeps idle
	// connections forever, so every distinct host a sandbox application touches
	// over cleartext left two sockets and their goroutines parked until the
	// process exited.
	//
	// dialDirect rather than a bare dialer, so that the cleartext path leaves
	// the sandbox through the same door every other path does. Assigned once,
	// here: http.Transport reads DialContext from whatever goroutine is running
	// RoundTrip, with no synchronisation, so reassigning it later would be a
	// data race rather than a configuration change.
	r.transport.DialContext = r.dialDirect
	r.transport.IdleConnTimeout = idleConnTimeout
	return r
}

// plainDial is the dialer for the connections that must not be judged: the
// loopback hop to a tunnel port. It is what r.transport.DialContext would have
// been.
func plainDial(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, network, addr)
}

// chainedTransport returns the transport that proxies through a tunnel port,
// building it once per port.
func (r *EgressProxy) chainedTransport(chainPort int) *http.Transport {
	r.chainedMu.Lock()
	defer r.chainedMu.Unlock()

	if t, ok := r.chained[chainPort]; ok {
		return t
	}
	proxyURL := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(chainPort))}
	t := r.transport.Clone()
	t.Proxy = http.ProxyURL(proxyURL)
	// The clone inherits DialContext, and the only address this transport ever
	// dials is the loopback tunnel port. Judging that against the egress rules
	// would refuse the tunnel itself the moment the default became deny — and it
	// would present as "everything broke when I turned the policy on".
	t.DialContext = plainDial
	r.chained[chainPort] = t
	return t
}

// proxyMode is which front ends a listener serves.
type proxyMode int

const (
	// proxyMixed serves HTTP and SOCKS5 on the same port, telling them apart by
	// their first byte. It is the default because a sandbox points HTTP_PROXY
	// and ALL_PROXY at one address, and two listeners would mean two of
	// everything for no gain.
	proxyMixed proxyMode = iota
	proxyHTTP
	proxySocks5
)

func (m proxyMode) String() string {
	switch m {
	case proxyHTTP:
		return "http"
	case proxySocks5:
		return "socks5"
	default:
		return "mixed"
	}
}

// parseProxyScheme splits an optional scheme off a listen address, the way gost
// and glider spell it. No scheme means both protocols.
//
// A port is always required. Defaulting one would be a listener on an address
// nobody asked for, which is the sort of thing that is discovered later, from
// the wrong end.
func parseProxyScheme(addr string) (proxyMode, string, error) {
	mode := proxyMixed
	if scheme, rest, found := strings.Cut(addr, "://"); found {
		switch scheme {
		case "mixed":
			mode = proxyMixed
		case "http":
			mode = proxyHTTP
		case "socks5":
			mode = proxySocks5
		default:
			return mode, "", fmt.Errorf("unsupported proxy scheme %q in %q (want mixed, http or socks5)", scheme, addr)
		}
		addr = rest
	}

	if _, port, err := net.SplitHostPort(addr); err != nil || port == "" {
		return mode, "", fmt.Errorf("bad proxy address %q: want host:port, :port or a scheme in front of one", addr)
	}
	return mode, addr, nil
}

// Start begins serving on addr, which may carry a scheme:
//
//	127.0.0.1:9090          HTTP and SOCKS5 on one port
//	mixed://127.0.0.1:9090  the same, spelled out
//	http://127.0.0.1:8080   HTTP only
//	socks5://127.0.0.1:1080 SOCKS5 only
//
// Keep the address on loopback unless something else is guarding the port. The
// egress proxy has no authentication of any kind: it relays to any host it is asked
// for, and hands anyone who reaches it the controlplane's injected credentials
// for every allowlisted domain. Its business is with processes inside this
// sandbox.
func (r *EgressProxy) Start(addr string) error {
	mode, hostPort, err := parseProxyScheme(addr)
	if err != nil {
		return fmt.Errorf("egress: %w", err)
	}

	// Checked before the listener exists, so a refused call leaves nothing
	// behind. A second Start used to overwrite the first listener and orphan
	// it: still accepting, with nobody holding a reference to close it.
	r.lifecycleMu.Lock()
	switch {
	case r.stopped:
		r.lifecycleMu.Unlock()
		return errors.New("egress: already closed")
	case r.listener != nil:
		current := r.listener.Addr()
		r.lifecycleMu.Unlock()
		return fmt.Errorf("egress: already listening on %s", current)
	}
	r.lifecycleMu.Unlock()

	ln, err := net.Listen("tcp", hostPort)
	if err != nil {
		return fmt.Errorf("egress listen on %s: %w", hostPort, err)
	}

	// A server rather than http.Serve: it is the only thing that can carry a
	// timeout, and the only thing Close can reach the live connections through.
	srv := &http.Server{
		Handler:           h2c.NewHandler(r, &http2.Server{}),
		ReadHeaderTimeout: serverReadHeaderTimeout.Get(),
		// `OPTIONS *` is forwarded like any other request; net/http would
		// otherwise answer it here, on behalf of a server it is not.
		DisableGeneralOptionsHandler: true,
	}

	if mode == proxyHTTP {
		r.lifecycleMu.Lock()
		r.listener = ln
		r.srv = srv
		r.lifecycleMu.Unlock()

		log.Printf("[vtunnel-egress] Listening on %s (HTTP)", ln.Addr())
		go r.serveHTTP(srv, ln)
		return nil
	}

	// An application in a sandbox has HTTP_PROXY for what speaks HTTP and
	// ALL_PROXY for what does not, and pointing both at one address is the
	// difference between one firewall rule and two. The two protocols are told
	// apart by their first byte.
	mixed := proxy.NewMixed(ln, peekTimeout.Get(), r.handleSocks5)

	r.lifecycleMu.Lock()
	r.listener = mixed
	if mode == proxyMixed {
		r.srv = srv
	}
	r.lifecycleMu.Unlock()

	log.Printf("[vtunnel-egress] Listening on %s (%s)", ln.Addr(), mode)
	if mode == proxySocks5 {
		go r.refuseNonSocks5(mixed)
		return nil
	}
	go r.serveHTTP(srv, mixed)
	return nil
}

func (r *EgressProxy) serveHTTP(srv *http.Server, ln net.Listener) {
	// Serve always ends with an error; the one Close causes is not news.
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("[vtunnel-egress] Stopped serving: %v", err)
	}
}

// refuseNonSocks5 drains what a SOCKS5-only listener is not there for. Hanging
// up says more than an HTTP error would: the operator asked for one protocol on
// this port, and something is speaking another.
func (r *EgressProxy) refuseNonSocks5(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		log.Printf("[vtunnel-egress] %s spoke something other than SOCKS5 to a socks5:// listener", conn.RemoteAddr())
		conn.Close()
	}
}

// handleSocks5 serves one SOCKS5 connection: learn where the client wants to
// go, then take exactly the same decision the CONNECT path takes.
//
// SOCKS5 exists here for the traffic that has no other way in — psql,
// redis-cli, ssh, anything that never reads HTTPS_PROXY. Such a client used to
// leave the sandbox directly, past the allowlist and past the credential the
// controlplane would have injected, not by decision but because nothing asked
// it where it was going.
//
// It contributes no authority of its own: the name it produces is matched
// against the same routes, and an unrouted one is dialled from the sandbox
// exactly as an unrouted CONNECT is.
func (r *EgressProxy) handleSocks5(conn net.Conn) {
	defer conn.Close()
	// A SOCKS5 connection never passes through the http.Server, so Close has no
	// other way to reach it.
	defer r.track(conn)()

	req, err := socks5.Accept(conn, peekTimeout.Get())
	if err != nil {
		log.Printf("[vtunnel-egress] SOCKS5: %v", err)
		return
	}

	// Without a policy, routes are the only vocabulary there is, and they are
	// written in names. A client configured as socks5:// resolves before it
	// asks, so its traffic would leave the sandbox with the allowlist never
	// consulted and the credential never injected — silently, which is the worst
	// way for a rule to fail. Refusing makes it an error the first time, and
	// forwarding the address explicitly is how it is allowed.
	//
	// A policy retires that rule rather than adding to it. Addresses are
	// first-class once there are rules written in them, so the literal is judged
	// like anything else — and judged the same way CONNECT judges it, which has
	// accepted literals all along. Keeping the refusal here as well would leave
	// the two front ends permanently disagreeing about the same destination.
	if r.policy.Load() == nil && isAddressLiteral(req.Target) {
		if _, routed := r.route(req.Target); !routed {
			log.Printf("[vtunnel-egress] SOCKS5 %s: refused, addresses are not routable — "+
				"use socks5h:// so the name reaches this proxy unresolved, or forward "+
				"the address itself if it is meant to be reachable", req.Target)
			req.Refuse(socks5.RepNotAllowed)
			return
		}
	}

	upstream, err := r.dialFor(context.Background(), req.Target, "SOCKS5")
	if err != nil {
		log.Printf("[vtunnel-egress] SOCKS5 %s: %v", req.Target, err)
		if errors.Is(err, errDenied) {
			// "Connection not allowed by ruleset" is what SOCKS5 has for exactly
			// this, and it is not what ReplyCode would guess from the text.
			req.Refuse(socks5.RepNotAllowed)
			return
		}
		req.Refuse(socks5.ReplyCode(err))
		return
	}
	defer upstream.Close()

	if err := req.Grant(); err != nil {
		return
	}
	dualStream(upstream, conn, conn)
}

// dialFor opens the connection a request for hostPort should get: through the
// tunnel when the domain is allowlisted, straight out of the sandbox when it is
// not. how names the front end, for the log.
//
// Every front end that ends in a byte pipe comes through here — CONNECT and
// SOCKS5 today — so that the same destination gets the same answer whichever
// door it arrived at. The cleartext HTTP path cannot: it hands its dial to
// net/http, which is why dialDirect is also the transport's DialContext.
func (r *EgressProxy) dialFor(ctx context.Context, hostPort, how string) (net.Conn, error) {
	if chainPort, ok := r.route(hostPort); ok {
		log.Printf("[vtunnel-egress] %s %s -> tunnel port %d", how, hostPort, chainPort)
		return r.dialChained(hostPort, chainPort)
	}

	log.Printf("[vtunnel-egress] %s %s -> direct", how, hostPort)
	return r.dialDirect(ctx, "tcp", hostPort)
}

// writeDialError answers a failed dial, telling a refusal apart from a failure.
//
// The two must not look alike. 403 says the rules refused this, and the fix is
// a rule; 502 says the destination could not be reached, and the fix is
// somewhere else entirely. An operator who cannot tell them apart from the
// response is left guessing, which is how egress policy gets switched off.
func writeDialError(w http.ResponseWriter, hostPort string, err error) {
	if errors.Is(err, errDenied) {
		log.Printf("[vtunnel-egress] %s: %v", hostPort, err)
		http.Error(w, "vtunnel: refused by the egress policy", http.StatusForbidden)
		return
	}
	http.Error(w, err.Error(), http.StatusBadGateway)
}

// dialDirect is the one place a connection leaves the sandbox. Everything that
// egresses without crossing the tunnel is dialled here, so that there is a
// single place for a rule to apply and a single place to audit that it did.
//
// The name is judged first, and the address afterwards — from inside the
// dialler, once per candidate. Splitting it that way is what closes the gap
// between checking and connecting: net.Dialer calls ControlContext after the
// socket exists and before connect(2), with the address the kernel is about to
// use, so a name that answers one way when it is checked and another when it is
// dialled has nowhere to slip through. Vetting a resolved list and then dialling
// the name again would have left exactly that gap; resolving it ourselves and
// dialling the survivors in a loop would have closed it and thrown away Happy
// Eyeballs, which is the thing that makes a dual-stack sandbox usable.
func (r *EgressProxy) dialDirect(ctx context.Context, network, hostPort string) (net.Conn, error) {
	policy := r.policy.Load()
	if policy == nil {
		conn, err := plainDial(ctx, network, hostPort)
		if err != nil {
			return nil, err
		}
		setTCPOptions(conn)
		return conn, nil
	}

	host, port, err := net.SplitHostPort(hostPort)
	if err != nil || host == "" {
		// An authority nothing can be matched against must not fall through to
		// the default. An empty host is a dialable address in Go, and it means
		// this machine.
		return nil, deniedError{what: hostPort + " is not a host and a port"}
	}

	nameVerdict := policy.matchName(host, port)
	if nameVerdict == verdictDeny {
		return nil, deniedError{what: host + " is denied by a name rule"}
	}
	if !policy.needsResolve(nameVerdict) {
		return nil, deniedError{what: host + " is not allowed by any rule, and the default is deny"}
	}

	dialer := &net.Dialer{
		Timeout: dialTimeout,
		ControlContext: func(_ context.Context, _, address string, _ syscall.RawConn) error {
			return policy.vet(address, nameVerdict)
		},
	}
	conn, err := dialer.DialContext(ctx, network, hostPort)
	if err != nil {
		return nil, err
	}
	setTCPOptions(conn)
	return conn, nil
}

// isAddressLiteral reports whether hostPort names a host by address rather than
// by name.
func isAddressLiteral(hostPort string) bool {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return false
	}
	return net.ParseIP(host) != nil
}

// lifecycle returns the state Start installed, as one consistent snapshot.
func (r *EgressProxy) lifecycle() (net.Listener, *http.Server) {
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()
	return r.listener, r.srv
}

// Addr returns the address the egress proxy listens on, or nil before Start.
func (r *EgressProxy) Addr() net.Addr {
	ln, _ := r.lifecycle()
	if ln == nil {
		return nil
	}
	return ln.Addr()
}

// Close stops serving, including connections already established. It is safe to
// call more than once.
//
// Closing only the listener left every live connection running — a keep-alive
// pool from the application, a CONNECT tunnel mid-transfer — with nothing the
// caller could reach them through.
func (r *EgressProxy) Close() {
	r.lifecycleMu.Lock()
	ln, srv, already := r.listener, r.srv, r.stopped
	r.stopped = true
	r.lifecycleMu.Unlock()

	if !already {
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
	}

	// net/http drops a connection from its own tracking the instant it is
	// hijacked, and a SOCKS5 connection never enters that tracking at all, so
	// srv.Close reaches neither. Both are here.
	r.closeDetached()

	r.transport.CloseIdleConnections()
	r.chainedMu.Lock()
	for _, t := range r.chained {
		t.CloseIdleConnections()
	}
	r.chainedMu.Unlock()
}

// SetRoutes makes domains reachable through chainPort, replacing any routes
// previously registered for that port. The client re-sends its full list on
// every reconnect, so replacing keeps the allowlist in step with it.
//
// Domains are stored as the controlplane spelled them. A domain without a port
// covers every port, the same way an egress rule without one does — both are
// read by bestDomainMatch, so a name resolves identically on either side.
func (r *EgressProxy) SetRoutes(chainPort int, domains []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for domain, port := range r.routes {
		if port == chainPort {
			delete(r.routes, domain)
		}
	}
	for _, domain := range domains {
		r.routes[domain] = chainPort
	}
	log.Printf("[vtunnel-egress] Routes for tunnel port %d: %v", chainPort, domains)
}

// route returns the tunnel port serving hostPort, if it is allowlisted.
func (r *EgressProxy) route(hostPort string) (int, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	pattern, ok := bestDomainMatch(r.routes, hostPort)
	if !ok {
		return 0, false
	}
	return r.routes[pattern], true
}

func (r *EgressProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		r.handleConnect(w, req)
		return
	}
	r.handleHTTP(w, req)
}

func (r *EgressProxy) handleConnect(w http.ResponseWriter, req *http.Request) {
	hostPort := req.Host
	if hostPort == "" {
		hostPort = req.URL.Host
	}

	if !isRoutableAuthority(hostPort) {
		log.Printf("[vtunnel-egress] CONNECT %q: not a host and port; refused", hostPort)
		http.Error(w, "vtunnel: CONNECT authority is not a host and port", http.StatusBadRequest)
		return
	}

	// Routed or not, the two used to be separate functions ending in the same
	// four lines. They are one call now, because that is the property worth
	// keeping: a CONNECT is decided in the one place SOCKS5 is decided, and the
	// client's TLS is untouched either way — it is terminated on the
	// controlplane, which is the only side holding the MITM CA.
	upstream, err := r.dialFor(req.Context(), hostPort, "CONNECT")
	if err != nil {
		writeDialError(w, hostPort, err)
		return
	}
	defer upstream.Close()

	switch req.ProtoMajor {
	case 1:
		serveHijack(w, upstream, r.track)
	default: // HTTP/2, HTTP/3
		serveH2Connect(w, req, upstream)
	}
}

// dialChained opens a connection to the controlplane proxy on the far side of
// chainPort and asks it, by CONNECT, for hostPort.
//
// Only the name travels: the controlplane matches it against its own routes and
// dials whatever those say. That is the whole reason there is no "give me a TCP
// connection to this address" message anywhere in this protocol — a sandbox
// that could name an address could name any address on the controlplane's
// network.
func (r *EgressProxy) dialChained(hostPort string, chainPort int) (net.Conn, error) {
	upstreamAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(chainPort))

	upstream, err := net.DialTimeout("tcp", upstreamAddr, dialTimeout)
	if err != nil {
		return nil, err
	}
	setTCPOptions(upstream)

	// dialTimeout covers only the dial. Without a deadline here a controlplane
	// that accepts TCP and then goes quiet — mid-reconnect, swapped out, a
	// wedged hop — would block this read forever. Cleared once the answer is
	// in, so the tunnel itself is not on a clock.
	upstream.SetDeadline(time.Now().Add(connectReplyTimeout))

	if _, err := fmt.Fprintf(upstream, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", hostPort, hostPort); err != nil {
		upstream.Close()
		return nil, err
	}

	// The answer is read before the client's connection is touched, so a
	// failure can still be reported as a status rather than a dead tunnel.
	br := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		upstream.Close()
		return nil, fmt.Errorf("upstream proxy: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		upstream.Close()
		return nil, fmt.Errorf("upstream proxy: %s", resp.Status)
	}
	upstream.SetDeadline(time.Time{})

	// br may already hold bytes the chained proxy sent after its 200.
	return newBufferedConn(upstream, br), nil
}

// serveUpgrade forwards a cleartext protocol upgrade, chaining it to the
// controlplane for a routed domain and dialling the host directly otherwise.
//
// The egress proxy still parses nothing beyond the request line and headers: the
// handshake is passed on as it arrived, and once the far side answers 101 the
// connection is a byte pipe. Interception, if any, happens on the controlplane
// exactly as it does for CONNECT.
func (r *EgressProxy) serveUpgrade(w http.ResponseWriter, req *http.Request, hostPort string) {
	// A client may address the egress proxy in either form: absolute-URI when it knows
	// it is talking to a proxy, origin-form when something else pointed it here.
	// Chaining writes the absolute form, so the URL has to carry a scheme and
	// host either way.
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	// This is the one path that cannot go through dialFor. Its tunnel hop speaks
	// the absolute form of an ordinary proxied request to the chain port, not
	// the CONNECT dialChained writes — an upgrade has to reach the controlplane
	// as a request, or the headers configured for the route never land in it. So
	// the tunnel branch dials loopback plainly, and only the direct branch is
	// egress.
	var (
		upstream  net.Conn
		err       error
		proxyForm bool
	)
	if chainPort, ok := r.route(hostPort); ok {
		target := net.JoinHostPort("127.0.0.1", strconv.Itoa(chainPort))
		proxyForm = true
		log.Printf("[vtunnel-egress] %s %s -> tunnel %s (%s upgrade)", req.Method, hostPort, target, req.Header.Get("Upgrade"))
		upstream, err = plainDial(req.Context(), "tcp", target)
	} else {
		log.Printf("[vtunnel-egress] %s %s -> direct (%s upgrade)", req.Method, hostPort, req.Header.Get("Upgrade"))
		upstream, err = r.dialDirect(req.Context(), "tcp", hostPort)
	}
	if err != nil {
		writeDialError(w, hostPort, err)
		return
	}
	defer upstream.Close()
	setTCPOptions(upstream)

	removeHopByHopForUpgrade(req.Header)
	// Tracked for the same reason a CONNECT is: an upgrade hijacks the
	// connection, and net/http stops managing it the moment it does.
	serveUpgrade(w, req, upstream, proxyForm, r.track)
}

func (r *EgressProxy) handleHTTP(w http.ResponseWriter, req *http.Request) {
	// A request with no Host names no destination. Synthesising one produced
	// ":80" — a perfectly dialable address in Go, meaning the local machine —
	// so a request nobody could route became a connection to this host's own
	// loopback. Inside a CONNECT the authority is known and routeHandler fills
	// it in; here there is nothing to fill it in from.
	if req.Host == "" && req.URL.Host == "" {
		w.Header().Set("Connection", "close")
		http.Error(w, "vtunnel: request has no Host header, destination unknown", http.StatusBadRequest)
		return
	}

	hostPort := req.Host
	if _, _, err := net.SplitHostPort(hostPort); err != nil {
		port := "80"
		if req.URL.Scheme == "https" {
			port = "443"
		}
		hostPort = net.JoinHostPort(hostPort, port)
	}

	// An upgrade cannot go through http.Transport at all: it has no way to hand
	// back a 101 and the connection under it. Cleartext ws:// therefore needs its
	// own path here, or it dies in the sandbox without ever reaching the tunnel.
	if isUpgradeRequest(req) {
		r.serveUpgrade(w, req, hostPort)
		return
	}

	transport := &r.transport
	if chainPort, ok := r.route(hostPort); ok {
		// Cleartext HTTP chains the same way, as an ordinary proxied request
		// in absolute-URI form.
		log.Printf("[vtunnel-egress] %s %s -> tunnel port %d", req.Method, hostPort, chainPort)
		transport = r.chainedTransport(chainPort)
	}

	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	// The request goes out as HTTP/1.1 whatever it arrived as: chaining rides
	// net/http's proxy support, which speaks nothing else. TE: trailers survives
	// that downgrade, though, and has to — it is what tells the far end trailers
	// are wanted, and a gRPC call that arrived here as h2c reports its status in
	// one. HTTP/1.1 carries trailers with chunked encoding, so asking is valid.
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1
	req.RequestURI = ""
	removeHopByHop(req.Header, true)

	resp, err := transport.RoundTrip(req)
	if err != nil {
		writeDialError(w, hostPort, err)
		return
	}
	defer resp.Body.Close()

	copyResponse(w, resp)
}
