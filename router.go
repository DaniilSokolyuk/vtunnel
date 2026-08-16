package vtunnel

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/vivid-money/vtunnel/internal/proxy"
	"github.com/vivid-money/vtunnel/internal/proxy/socks5"
)

// Router is the sandbox-side forward proxy. It is deliberately dumb: it holds
// an allowlist of domains and nothing else — no CA, no credentials, no TLS
// termination.
//
// The domain comes from the CONNECT request line, which the application sends
// in cleartext before any TLS, so routing needs no decryption. Allowlisted
// requests are chained to the controlplane's proxy through a tunnel port,
// exactly like any HTTP proxy chaining to an upstream proxy; everything else is
// dialed directly, so unmapped traffic still egresses from the sandbox.
type Router struct {
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
	// goroutines. The once is created with the Router and never reassigned.
	lifecycleMu sync.Mutex
	listener    net.Listener
	srv         *http.Server
	once        sync.Once
}

// connectReplyTimeout bounds the wait for a chained proxy to answer a CONNECT.
// A variable rather than a constant so tests need not wait it out.
var connectReplyTimeout = dialTimeout

func newRouter() *Router {
	return &Router{
		routes:  make(map[string]int),
		chained: make(map[int]*http.Transport),
	}
}

// chainedTransport returns the transport that proxies through a tunnel port,
// building it once per port.
func (r *Router) chainedTransport(chainPort int) *http.Transport {
	r.chainedMu.Lock()
	defer r.chainedMu.Unlock()

	if t, ok := r.chained[chainPort]; ok {
		return t
	}
	proxyURL := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(chainPort))}
	t := r.transport.Clone()
	t.Proxy = http.ProxyURL(proxyURL)
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
// router has no authentication of any kind: it relays to any host it is asked
// for, and hands anyone who reaches it the controlplane's injected credentials
// for every allowlisted domain. Its business is with processes inside this
// sandbox.
func (r *Router) Start(addr string) error {
	mode, hostPort, err := parseProxyScheme(addr)
	if err != nil {
		return fmt.Errorf("router: %w", err)
	}

	ln, err := net.Listen("tcp", hostPort)
	if err != nil {
		return fmt.Errorf("router listen on %s: %w", hostPort, err)
	}

	// A server rather than http.Serve: it is the only thing that can carry a
	// timeout, and the only thing Close can reach the live connections through.
	srv := &http.Server{
		Handler:           h2c.NewHandler(r, &http2.Server{}),
		ReadHeaderTimeout: serverReadHeaderTimeout,
	}

	if mode == proxyHTTP {
		r.lifecycleMu.Lock()
		r.listener = ln
		r.srv = srv
		r.lifecycleMu.Unlock()

		log.Printf("[vtunnel-router] Listening on %s (HTTP)", ln.Addr())
		go r.serveHTTP(srv, ln)
		return nil
	}

	// An application in a sandbox has HTTP_PROXY for what speaks HTTP and
	// ALL_PROXY for what does not, and pointing both at one address is the
	// difference between one firewall rule and two. The two protocols are told
	// apart by their first byte.
	mixed := proxy.NewMixed(ln, peekTimeout, r.handleSocks5)

	r.lifecycleMu.Lock()
	r.listener = mixed
	if mode == proxyMixed {
		r.srv = srv
	}
	r.lifecycleMu.Unlock()

	log.Printf("[vtunnel-router] Listening on %s (%s)", ln.Addr(), mode)
	if mode == proxySocks5 {
		go r.refuseNonSocks5(mixed)
		return nil
	}
	go r.serveHTTP(srv, mixed)
	return nil
}

func (r *Router) serveHTTP(srv *http.Server, ln net.Listener) {
	// Serve always ends with an error; the one Close causes is not news.
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("[vtunnel-router] Stopped serving: %v", err)
	}
}

// refuseNonSocks5 drains what a SOCKS5-only listener is not there for. Hanging
// up says more than an HTTP error would: the operator asked for one protocol on
// this port, and something is speaking another.
func (r *Router) refuseNonSocks5(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		log.Printf("[vtunnel-router] %s spoke something other than SOCKS5 to a socks5:// listener", conn.RemoteAddr())
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
func (r *Router) handleSocks5(conn net.Conn) {
	defer conn.Close()

	req, err := socks5.Accept(conn, peekTimeout)
	if err != nil {
		log.Printf("[vtunnel-router] SOCKS5: %v", err)
		return
	}

	// Policy is written in names, and an address cannot be matched against one.
	// A client configured as socks5:// resolves before it asks, so its traffic
	// would leave the sandbox with the allowlist never consulted and the
	// credential never injected — silently, which is the worst way for a rule
	// to fail. Refusing makes it an error the first time, and forwarding the
	// address explicitly is how it is allowed.
	if isAddressLiteral(req.Target) {
		if _, routed := r.route(req.Target); !routed {
			log.Printf("[vtunnel-router] SOCKS5 %s: refused, addresses are not routable — "+
				"use socks5h:// so the name reaches this proxy unresolved, or forward "+
				"the address itself if it is meant to be reachable", req.Target)
			req.Refuse(socks5.RepNotAllowed)
			return
		}
	}

	upstream, err := r.dialFor(req.Target, "SOCKS5")
	if err != nil {
		log.Printf("[vtunnel-router] SOCKS5 %s: %v", req.Target, err)
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
func (r *Router) dialFor(hostPort, how string) (net.Conn, error) {
	if chainPort, ok := r.route(hostPort); ok {
		log.Printf("[vtunnel-router] %s %s -> tunnel port %d", how, hostPort, chainPort)
		return r.dialChained(hostPort, chainPort)
	}

	log.Printf("[vtunnel-router] %s %s -> direct", how, hostPort)
	conn, err := net.DialTimeout("tcp", hostPort, dialTimeout)
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
func (r *Router) lifecycle() (net.Listener, *http.Server) {
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()
	return r.listener, r.srv
}

// Addr returns the address the router listens on, or nil before Start.
func (r *Router) Addr() net.Addr {
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
func (r *Router) Close() {
	r.once.Do(func() {
		ln, srv := r.lifecycle()
		if srv != nil {
			srv.Close() // closes the listener too
		} else if ln != nil {
			ln.Close()
		}
	})

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
// A domain without a port is registered for both :80 and :443.
func (r *Router) SetRoutes(chainPort int, domains []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for domain, port := range r.routes {
		if port == chainPort {
			delete(r.routes, domain)
		}
	}
	for _, domain := range domains {
		if _, _, err := net.SplitHostPort(domain); err != nil {
			r.routes[net.JoinHostPort(domain, "80")] = chainPort
			r.routes[net.JoinHostPort(domain, "443")] = chainPort
			continue
		}
		r.routes[domain] = chainPort
	}
	log.Printf("[vtunnel-router] Routes for tunnel port %d: %v", chainPort, domains)
}

// route returns the tunnel port serving hostPort, if it is allowlisted.
func (r *Router) route(hostPort string) (int, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	pattern, ok := bestDomainMatch(r.routes, hostPort)
	if !ok {
		return 0, false
	}
	return r.routes[pattern], true
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		r.handleConnect(w, req)
		return
	}
	r.handleHTTP(w, req)
}

func (r *Router) handleConnect(w http.ResponseWriter, req *http.Request) {
	hostPort := req.Host
	if hostPort == "" {
		hostPort = req.URL.Host
	}

	if chainPort, ok := r.route(hostPort); ok {
		r.chainConnect(w, req, hostPort, chainPort)
		return
	}

	log.Printf("[vtunnel-router] CONNECT %s -> direct", hostPort)
	targetConn, err := net.DialTimeout("tcp", hostPort, dialTimeout)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	switch req.ProtoMajor {
	case 1:
		serveHijack(w, targetConn)
	default: // HTTP/2, HTTP/3
		serveH2Connect(w, req, targetConn)
	}
}

// chainConnect forwards the CONNECT verbatim to the controlplane proxy on the
// far side of chainPort and then pipes bytes. The client's TLS is never
// touched here — it is terminated on the controlplane, which is the only side
// holding the MITM CA.
func (r *Router) chainConnect(w http.ResponseWriter, req *http.Request, hostPort string, chainPort int) {
	upstreamConn, err := r.dialChained(hostPort, chainPort)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer upstreamConn.Close()

	switch req.ProtoMajor {
	case 1:
		serveHijack(w, upstreamConn)
	default:
		serveH2Connect(w, req, upstreamConn)
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
func (r *Router) dialChained(hostPort string, chainPort int) (net.Conn, error) {
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
// The router still parses nothing beyond the request line and headers: the
// handshake is passed on as it arrived, and once the far side answers 101 the
// connection is a byte pipe. Interception, if any, happens on the controlplane
// exactly as it does for CONNECT.
func (r *Router) serveUpgrade(w http.ResponseWriter, req *http.Request, hostPort string) {
	// A client may address the router in either form: absolute-URI when it knows
	// it is talking to a proxy, origin-form when something else pointed it here.
	// Chaining writes the absolute form, so the URL has to carry a scheme and
	// host either way.
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	target, proxyForm := hostPort, false
	if chainPort, ok := r.route(hostPort); ok {
		target = net.JoinHostPort("127.0.0.1", strconv.Itoa(chainPort))
		// The far side is the controlplane proxy, which expects the absolute
		// form a proxied request carries.
		proxyForm = true
		log.Printf("[vtunnel-router] %s %s -> tunnel %s (%s upgrade)", req.Method, hostPort, target, req.Header.Get("Upgrade"))
	} else {
		log.Printf("[vtunnel-router] %s %s -> direct (%s upgrade)", req.Method, hostPort, req.Header.Get("Upgrade"))
	}

	upstream, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	setTCPOptions(upstream)

	removeHopByHopForUpgrade(req.Header)
	serveUpgrade(w, req, upstream, proxyForm, nil)
}

func (r *Router) handleHTTP(w http.ResponseWriter, req *http.Request) {
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
		log.Printf("[vtunnel-router] %s %s -> tunnel port %d", req.Method, hostPort, chainPort)
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
	keepTE := req.ProtoMajor == 2
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1
	req.RequestURI = ""
	removeHopByHop(req.Header, keepTE)

	resp, err := transport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyResponse(w, resp)
}
