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
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func (s *Server) SetDomainMapping(domain, target string) {
	s.domainMu.Lock()
	s.domainMap[domain] = target
	s.domainMu.Unlock()
	log.Printf("[vtunnel-proxy] Domain mapping added: %s -> %s", domain, target)
}

func (s *Server) RemoveDomainMapping(domain string) {
	s.domainMu.Lock()
	delete(s.domainMap, domain)
	s.domainMu.Unlock()
	log.Printf("[vtunnel-proxy] Domain mapping removed: %s", domain)
}

func (s *Server) resolveDomain(host string) (string, bool) {
	s.domainMu.RLock()
	target, ok := s.domainMap[host]
	s.domainMu.RUnlock()
	return target, ok
}

func (s *Server) StartProxy(addr string) error {
	handler := &proxyHandler{server: s}
	if s.mitmCA != nil {
		cc, err := newCertCache(*s.mitmCA)
		if err != nil {
			return fmt.Errorf("init MITM cert cache: %w", err)
		}
		handler.certCache = cc
	}

	h2s := &http2.Server{}
	h2cHandler := h2c.NewHandler(handler, h2s)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("proxy listen on %s: %w", addr, err)
	}

	s.proxyListener = ln
	s.proxyDone = make(chan struct{})
	s.proxyOnce = sync.Once{}

	log.Printf("[vtunnel-proxy] Listening on %s", addr)

	go http.Serve(ln, h2cHandler)

	return nil
}

func (s *Server) CloseProxy() {
	s.proxyOnce.Do(func() {
		if s.proxyDone != nil {
			close(s.proxyDone)
		}
		if s.proxyListener != nil {
			s.proxyListener.Close()
		}
	})
}

// proxyHandler implements http.Handler for the forward proxy.
type proxyHandler struct {
	server    *Server
	certCache *certCache // nil when no MITM CA
	transport http.Transport
	h2cProbed sync.Map // target → bool
}

func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
		return
	}
	h.handleHTTP(w, r)
}

func (h *proxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	hostPort := r.Host
	if hostPort == "" {
		hostPort = r.URL.Host
	}

	// Check domain mapping
	mapped, isMapped := h.server.resolveDomain(hostPort)

	// MITM path: intercept TLS for mapped domains
	if h.certCache != nil && isMapped {
		log.Printf("[vtunnel-proxy] CONNECT MITM %s", hostPort)
		h.handleConnectMITM(w, r, mapped)
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

	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
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

func (h *proxyHandler) handleConnectMITM(w http.ResponseWriter, r *http.Request, mappedTarget string) {
	// Get a net.Conn to the client — works for both HTTP/1.x and HTTP/2
	var rawConn net.Conn

	switch r.ProtoMajor {
	case 1:
		clientConn, brw, err := hijack(w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer clientConn.Close()
		brw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		brw.Flush()
		rawConn = clientConn
	default: // HTTP/2+
		w.WriteHeader(http.StatusOK)
		if err := http.NewResponseController(w).Flush(); err != nil {
			return
		}
		rawConn = newH2StreamConn(r.Body, w)
		defer rawConn.Close()
	}

	tlsConn := tls.Server(rawConn, &tls.Config{
		GetCertificate: h.certCache.getCert,
		NextProtos:     []string{"h2", "http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[vtunnel-proxy] MITM TLS handshake failed: %v", err)
		return
	}
	defer tlsConn.Close()

	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		h.serveMITMH2(tlsConn, mappedTarget)
		return
	}

	h.serveMITMH1(tlsConn, mappedTarget)
}

func (h *proxyHandler) probeH2C(target string) bool {
	if v, ok := h.h2cProbed.Load(target); ok {
		return v.(bool)
	}
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		h.h2cProbed.Store(target, false)
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	// HTTP/2 connection preface
	if _, err := conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		h.h2cProbed.Store(target, false)
		return false
	}
	buf := make([]byte, 9) // h2 frame header
	if _, err := io.ReadFull(conn, buf); err != nil {
		h.h2cProbed.Store(target, false)
		return false
	}
	ok := buf[3] == 0x04 // SETTINGS frame type
	h.h2cProbed.Store(target, ok)
	return ok
}

func (h *proxyHandler) serveMITMH2(tlsConn *tls.Conn, target string) {
	var rt http.RoundTripper
	scheme := "http"

	if tlsHost, ok := h.server.tlsUpstreamHost(target); ok {
		// Proxy-side TLS: connect to tunnel port, do TLS with real server's hostname.
		scheme = "https"
		rt = &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				conn, err := net.DialTimeout(network, target, 10*time.Second)
				if err != nil {
					return nil, err
				}
				tlsC := tls.Client(conn, &tls.Config{
					ServerName: tlsHost,
					NextProtos: []string{"h2"},
				})
				if err := tlsC.HandshakeContext(ctx); err != nil {
					conn.Close()
					return nil, err
				}
				return tlsC, nil
			},
		}
	} else if h.probeH2C(target) {
		rt = &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return net.DialTimeout(network, addr, 10*time.Second)
			},
		}
	} else {
		rt = &h.transport
	}

	h2srv := &http2.Server{}
	h2srv.ServeConn(tlsConn, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.URL.Scheme = scheme
			r.URL.Host = target
			r.RequestURI = ""
			removeHopByHop(r.Header)

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
			removeHopByHop(w.Header())
			w.WriteHeader(resp.StatusCode)
			flushingCopy(w, resp.Body)
			for k, vv := range resp.Trailer {
				for _, v := range vv {
					w.Header().Set(http.TrailerPrefix+k, v)
				}
			}
		}),
	})
}

func (h *proxyHandler) serveMITMH1(tlsConn *tls.Conn, target string) {
	var transport *http.Transport

	if tlsHost, ok := h.server.tlsUpstreamHost(target); ok {
		// Proxy-side TLS: connect to tunnel port, do TLS with real server's hostname.
		transport = &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := net.DialTimeout(network, target, 10*time.Second)
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
		transport = &h.transport
	}

	br := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}

		if transport != &h.transport {
			req.URL.Scheme = "https"
		} else {
			req.URL.Scheme = "http"
		}
		req.URL.Host = target
		req.RequestURI = ""
		removeHopByHop(req.Header)

		resp, err := transport.RoundTrip(req)
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

func (h *proxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	hostPort := r.Host
	if _, _, err := net.SplitHostPort(hostPort); err != nil {
		port := "80"
		if r.URL.Scheme == "https" {
			port = "443"
		}
		hostPort = net.JoinHostPort(hostPort, port)
	}

	if mapped, ok := h.server.resolveDomain(hostPort); ok {
		log.Printf("[vtunnel-proxy] %s %s %s -> %s", r.URL.Scheme, r.Method, hostPort, mapped)
		r.URL.Host = mapped
		r.URL.Scheme = "http"
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
	removeHopByHop(r.Header)

	resp, err := h.transport.RoundTrip(r)
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
	removeHopByHop(w.Header())
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// serveHijack handles HTTP/1.x CONNECT by hijacking the connection.
func serveHijack(w http.ResponseWriter, targetConn net.Conn) {
	clientConn, brw, err := hijack(w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	brw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	brw.Flush()

	// Flush any buffered data from the client
	if n := brw.Reader.Buffered(); n > 0 {
		buf, _ := brw.Peek(n)
		targetConn.Write(buf)
	}

	dualStream(targetConn, clientConn, clientConn)
}

// hijack takes over the underlying connection from the ResponseWriter.
func hijack(w http.ResponseWriter) (net.Conn, *bufio.ReadWriter, error) {
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return nil, nil, fmt.Errorf("hijack failed: %w", err)
	}
	return conn, brw, nil
}

// serveH2Connect handles HTTP/2+ CONNECT by streaming via ResponseWriter and Request.Body.
func serveH2Connect(w http.ResponseWriter, r *http.Request, targetConn net.Conn) {
	defer r.Body.Close()
	w.WriteHeader(http.StatusOK)
	if err := http.NewResponseController(w).Flush(); err != nil {
		return
	}
	dualStream(targetConn, r.Body, w)
}

// dualStream copies data bidirectionally between target and client.
func dualStream(target net.Conn, clientReader io.Reader, clientWriter io.Writer) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		flushingCopy(clientWriter, target)
		if cw, ok := clientWriter.(closeWriter); ok {
			cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		bufPtr := bufPool.Get().(*[]byte)
		buf := (*bufPtr)[:cap(*bufPtr)]
		io.CopyBuffer(target, clientReader, buf)
		bufPool.Put(bufPtr)
		if cw, ok := target.(closeWriter); ok {
			cw.CloseWrite()
		}
	}()
	wg.Wait()
}

type closeWriter interface {
	CloseWrite() error
}

// flushingCopy copies from src to dst, flushing after each write if dst supports it.
func flushingCopy(dst io.Writer, src io.Reader) {
	rw, isRW := dst.(http.ResponseWriter)
	bufPtr := bufPool.Get().(*[]byte)
	buf := (*bufPtr)[:cap(*bufPtr)]
	defer bufPool.Put(bufPtr)

	if !isRW {
		io.CopyBuffer(dst, src, buf)
		return
	}

	rc := http.NewResponseController(rw)
	for {
		nr, readErr := src.Read(buf)
		if nr > 0 {
			nw, writeErr := dst.Write(buf[:nr])
			if writeErr != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
			if nw != nr {
				return
			}
		}
		if readErr != nil {
			return
		}
	}
}

var bufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 32*1024)
		return &buf
	},
}

// h2StreamConn wraps an HTTP/2 stream (Request.Body + ResponseWriter) as a net.Conn
// so that tls.Server can perform a TLS handshake over it.
type h2StreamConn struct {
	r  io.ReadCloser
	w  io.Writer
	rc *http.ResponseController
}

func newH2StreamConn(r io.ReadCloser, w http.ResponseWriter) *h2StreamConn {
	return &h2StreamConn{r: r, w: w, rc: http.NewResponseController(w)}
}

func (c *h2StreamConn) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *h2StreamConn) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if err != nil {
		return n, err
	}
	if err := c.rc.Flush(); err != nil {
		return n, err
	}
	return n, nil
}
func (c *h2StreamConn) Close() error                       { return c.r.Close() }
func (c *h2StreamConn) LocalAddr() net.Addr                { return h2Addr{} }
func (c *h2StreamConn) RemoteAddr() net.Addr               { return h2Addr{} }
func (c *h2StreamConn) SetDeadline(t time.Time) error      { return c.rc.SetWriteDeadline(t) }
func (c *h2StreamConn) SetReadDeadline(t time.Time) error  { return c.rc.SetReadDeadline(t) }
func (c *h2StreamConn) SetWriteDeadline(t time.Time) error { return c.rc.SetWriteDeadline(t) }

type h2Addr struct{}

func (h2Addr) Network() string { return "h2" }
func (h2Addr) String() string  { return "h2-stream" }

var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopByHop(h http.Header) {
	for _, key := range strings.Split(h.Get("Connection"), ",") {
		h.Del(strings.TrimSpace(key))
	}
	for _, key := range hopByHopHeaders {
		h.Del(key)
	}
}
