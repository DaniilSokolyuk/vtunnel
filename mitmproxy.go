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

// MITMProxy is an HTTP/CONNECT forward proxy that routes mapped domains to
// configured targets and passes everything else through directly.
//
// With a MITM CA configured it terminates TLS for mapped domains, generating
// leaf certificates on the fly, so per-domain headers can be injected into the
// forwarded requests. Without one it falls back to a raw byte pipe and the
// client's TLS travels end-to-end.
//
// The type owns all of its routing state and depends on neither Server nor
// Client, so it can run on either side of a tunnel.
type MITMProxy struct {
	domainMap     map[string]string
	domainHeaders map[string]http.Header // same keys as domainMap
	domainMu      sync.RWMutex

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

// NewMITMProxy creates a proxy with no domain mappings.
func NewMITMProxy(opts ...MITMProxyOption) *MITMProxy {
	p := &MITMProxy{
		domainMap:     make(map[string]string),
		domainHeaders: make(map[string]http.Header),
		tlsUpstream:   make(map[string]string),
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

func (p *MITMProxy) SetDomainMapping(domain, target string) {
	p.domainMu.Lock()
	p.domainMap[domain] = target
	p.domainMu.Unlock()
	log.Printf("[vtunnel-proxy] Domain mapping added: %s -> %s", domain, target)
}

func (p *MITMProxy) RemoveDomainMapping(domain string) {
	p.domainMu.Lock()
	delete(p.domainMap, domain)
	delete(p.domainHeaders, domain)
	p.domainMu.Unlock()
	log.Printf("[vtunnel-proxy] Domain mapping removed: %s", domain)
}

// SetDomainHeaders registers headers that the MITM proxy injects into every
// request routed to the given domain mapping. The key must match a key already
// (or later) passed to SetDomainMapping — typically "host:port" including
// wildcard forms (e.g. "*.example.test:443").
func (p *MITMProxy) SetDomainHeaders(domain string, headers http.Header) {
	p.domainMu.Lock()
	if headers == nil {
		delete(p.domainHeaders, domain)
	} else {
		p.domainHeaders[domain] = headers.Clone()
	}
	p.domainMu.Unlock()
	log.Printf("[vtunnel-proxy] Domain headers set: %s (%d)", domain, len(headers))
}

// SetTLSUpstream records that target needs proxy-side TLS, using host as the
// SNI name. This lets the proxy control ALPN on the upstream connection
// instead of relying on TLS being terminated further down the path.
func (p *MITMProxy) SetTLSUpstream(target, host string) {
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

func (p *MITMProxy) resolveDomain(host string) (string, http.Header, bool) {
	p.domainMu.RLock()
	defer p.domainMu.RUnlock()

	pattern, ok := bestDomainMatch(p.domainMap, host)
	if !ok {
		return "", nil, false
	}
	return p.domainMap[pattern], p.domainHeaders[pattern], true
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

	// Check domain mapping
	mapped, injectHeaders, isMapped := p.resolveDomain(hostPort)

	// A mapped domain may carry cleartext h2c gRPC, not only TLS.
	if p.certCache != nil && isMapped {
		p.handleConnectMITM(w, r, hostPort, mapped, injectHeaders)
		return
	}

	// Tunnel path: dial target and pipe bytes
	target := hostPort
	if isMapped {
		log.Printf("[vtunnel-proxy] CONNECT %s -> %s", hostPort, mapped)
		target = mapped
	} else {
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
func (p *MITMProxy) handleConnectMITM(w http.ResponseWriter, r *http.Request, connectAuthority, mappedTarget string, injectHeaders http.Header) {
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
		p.serveMITMTLS(tunnelConn, connectAuthority, mappedTarget, injectHeaders)
	case isH2C && overHijackedSocket:
		defer tunnelConn.Close()
		log.Printf("[vtunnel-proxy] CONNECT %s -> %s (cleartext h2c, injecting headers)", connectAuthority, mappedTarget)
		// No pre-established upstream here: the client came in cleartext, so
		// there was no client handshake to mirror an upstream ALPN onto.
		p.serveInjectingH2(tunnelConn, mappedTarget, injectHeaders, nil)
	default:
		defer tunnelConn.Close()
		log.Printf("[vtunnel-proxy] CONNECT %s -> %s (cleartext, raw pipe)", connectAuthority, mappedTarget)
		if len(injectHeaders) > 0 {
			// Raw byte pipe can't inject headers; only HTTP/1.1-CONNECT h2c is terminated.
			log.Printf("[vtunnel-proxy] WARNING: %s: %d header(s) NOT injected (raw pipe)", connectAuthority, len(injectHeaders))
		}
		dialAndPipe(mappedTarget, tunnelConn)
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
func (p *MITMProxy) serveMITMTLS(clientConn net.Conn, connectAuthority, target string, injectHeaders http.Header) {
	log.Printf("[vtunnel-proxy] CONNECT MITM %s", connectAuthority)
	connectHost := hostFromAuthority(connectAuthority)
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
		p.serveInjectingH2(tlsConn, target, injectHeaders, up)
		return
	}
	p.serveMITMH1(tlsConn, target, injectHeaders, up)
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

// serveInjectingH2 serves an already-established HTTP/2 client connection —
// TLS-terminated or cleartext h2c — and proxies each request to target with the
// configured headers injected. It works on any net.Conn, so MITM'd TLS and raw
// h2c share one path.
func (p *MITMProxy) serveInjectingH2(clientConn net.Conn, target string, injectHeaders http.Header, up *upstreamTLSConn) {
	var rt http.RoundTripper
	scheme := "http"

	if up != nil {
		// Upstream TLS is already up and negotiated; reuse it instead of
		// handshaking a second time.
		scheme = "https"
		rt = p.upstreamRoundTripper(up)
	} else if tlsHost, ok := p.tlsUpstreamHost(target); ok {
		// Proxy-side TLS: connect to tunnel port, do TLS with real server's hostname.
		scheme = "https"
		dialer := &net.Dialer{Timeout: dialTimeout}
		transport := p.transport.Clone()
		transport.ForceAttemptHTTP2 = true
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
		transport.TLSClientConfig.NextProtos = []string{"h2", "http/1.1"}

		rt = transport
	} else if p.probeH2C(target) {
		rt = &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return net.DialTimeout(network, addr, dialTimeout)
			},
		}
	} else {
		rt = &p.transport
	}

	h2srv := &http2.Server{}
	h2srv.ServeConn(clientConn, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.URL.Scheme = scheme
			r.URL.Host = target
			r.RequestURI = ""
			removeHopByHop(r.Header, true)
			injectConfiguredHeaders(r.Header, injectHeaders)

			resp, err := rt.RoundTrip(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()

			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			for k := range resp.Trailer {
				w.Header().Add("Trailer", k)
			}
			removeHopByHop(w.Header(), false)
			w.WriteHeader(resp.StatusCode)
			flushingCopy(w, resp.Body)
			forwardTrailers(w, resp)
		}),
	})
}

func (p *MITMProxy) serveMITMH1(tlsConn *tls.Conn, target string, injectHeaders http.Header, up *upstreamTLSConn) {
	var rt http.RoundTripper
	upstreamIsTLS := true

	if up != nil {
		// Upstream TLS is already up and negotiated; reuse it.
		rt = p.upstreamRoundTripper(up)
	} else if tlsHost, ok := p.tlsUpstreamHost(target); ok {
		// Proxy-side TLS: connect to tunnel port, do TLS with real server's hostname.
		rt = &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := net.DialTimeout(network, target, dialTimeout)
				if err != nil {
					return nil, err
				}
				tlsC := tls.Client(conn, &tls.Config{
					ServerName: tlsHost,
					NextProtos: []string{"http/1.1"},
				})
				if err := tlsC.HandshakeContext(ctx); err != nil {
					conn.Close()
					return nil, err
				}
				return tlsC, nil
			},
		}
	} else {
		rt = &p.transport
		upstreamIsTLS = false
	}

	br := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}

		if upstreamIsTLS {
			req.URL.Scheme = "https"
		} else {
			req.URL.Scheme = "http"
		}
		req.URL.Host = target
		req.RequestURI = ""
		removeHopByHop(req.Header, false)
		injectConfiguredHeaders(req.Header, injectHeaders)

		resp, err := rt.RoundTrip(req)
		if err != nil {
			resp = &http.Response{
				StatusCode: http.StatusBadGateway,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Body:       http.NoBody,
			}
		}

		resp.Write(tlsConn)
		resp.Body.Close()

		if req.Close || resp.Close {
			return
		}
	}
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

	if mapped, injectHeaders, ok := p.resolveDomain(hostPort); ok {
		log.Printf("[vtunnel-proxy] %s %s %s -> %s", r.URL.Scheme, r.Method, hostPort, mapped)
		r.URL.Host = mapped
		r.URL.Scheme = "http"
		injectConfiguredHeaders(r.Header, injectHeaders)
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
	r.RequestURI = ""
	removeHopByHop(r.Header, false)

	resp, err := p.transport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	removeHopByHop(w.Header(), false)
	w.WriteHeader(resp.StatusCode)
	// flushingCopy preserves event-by-event delivery for streaming responses
	// (text/event-stream from LLM proxies, gRPC-web, long-poll endpoints).
	// Plain io.Copy leaves the http.ResponseWriter's bufio buffer un-flushed
	// between writes, batching SSE events into one chunk at end-of-body.
	flushingCopy(w, resp.Body)
	forwardTrailers(w, resp)
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
