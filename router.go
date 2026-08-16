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
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
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

// Start begins serving on addr.
//
// Keep addr on loopback unless something else is guarding the port. The router
// has no authentication of any kind: it relays to any host it is asked for, and
// hands anyone who reaches it the controlplane's injected credentials for every
// allowlisted domain. Its business is with processes inside this sandbox.
func (r *Router) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("router listen on %s: %w", addr, err)
	}

	// A server rather than http.Serve: it is the only thing that can carry a
	// timeout, and the only thing Close can reach the live connections through.
	srv := &http.Server{
		Handler:           h2c.NewHandler(r, &http2.Server{}),
		ReadHeaderTimeout: serverReadHeaderTimeout,
	}

	r.lifecycleMu.Lock()
	r.listener = ln
	r.srv = srv
	r.lifecycleMu.Unlock()

	log.Printf("[vtunnel-router] Listening on %s", ln.Addr())
	go func() {
		// Serve always ends with an error; the one Close causes is not news.
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[vtunnel-router] Stopped serving: %v", err)
		}
	}()
	return nil
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
	upstreamAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(chainPort))
	log.Printf("[vtunnel-router] CONNECT %s -> tunnel %s", hostPort, upstreamAddr)

	upstream, err := net.DialTimeout("tcp", upstreamAddr, dialTimeout)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	setTCPOptions(upstream)

	// dialTimeout covers only the dial. Without a deadline here a controlplane
	// that accepts TCP and then goes quiet — mid-reconnect, swapped out, a
	// wedged hop — would block this read forever, and the promise in the
	// comment below could never be kept. Cleared once the answer is in, so the
	// tunnel itself is not on a clock.
	upstream.SetDeadline(time.Now().Add(connectReplyTimeout))

	if _, err := fmt.Fprintf(upstream, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", hostPort, hostPort); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// Read the chained proxy's answer before touching the client's connection,
	// so a failure can still be reported as a status rather than a dead tunnel.
	br := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream proxy: %v", err), http.StatusBadGateway)
		return
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("upstream proxy: %s", resp.Status), http.StatusBadGateway)
		return
	}
	upstream.SetDeadline(time.Time{})

	// br may already hold bytes the chained proxy sent after its 200.
	upstreamConn := newBufferedConn(upstream, br)

	switch req.ProtoMajor {
	case 1:
		serveHijack(w, upstreamConn)
	default:
		serveH2Connect(w, req, upstreamConn)
	}
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
