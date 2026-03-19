package vtunnel

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/http2"
)

const (
	defaultKeepAlive   = 30 * time.Second
	streamWaitTimeout  = 35 * time.Second
)

// tunnelAssignment represents a TCP connection waiting to be paired with a tunnel stream.
type tunnelAssignment struct {
	port    int
	tcpConn net.Conn
	done    chan struct{} // closed when pipe completes
}

// Server handles reverse tunnel connections from clients over h2mux-over-WebSocket.
type Server struct {
	keepAlive    time.Duration
	clientPubKey ed25519.PublicKey // nil = no auth
	streamPool   chan tunnelAssignment

	// Persistent listeners (survive reconnections)
	listeners   map[int]net.Listener
	listenersMu sync.Mutex

	// Proxy state (survives reconnections)
	domainMap     map[string]string
	domainMu      sync.RWMutex
	proxyListener net.Listener
	proxyDone     chan struct{}
	proxyOnce     sync.Once

	// MITM CA certificate for HTTPS interception (nil = transparent tunnel)
	mitmCA *tls.Certificate

	// tlsUpstream tracks tunnel targets that need proxy-side TLS.
	// Key: "127.0.0.1:<tunnelPort>", Value: original hostname (for SNI).
	// Populated by handleListen when MITM is active and target port is 443.
	tlsUpstream   map[string]string
	tlsUpstreamMu sync.RWMutex
}

// ServerOption configures a Server.
type ServerOption func(*Server)

// WithServerKeepAlive sets the keepalive ping interval for the server.
func WithServerKeepAlive(d time.Duration) ServerOption {
	return func(s *Server) {
		s.keepAlive = d
	}
}

// WithProxyMitmCA sets the CA certificate used for HTTPS MITM interception.
// When set, the proxy will decrypt HTTPS traffic for mapped domains,
// generating certificates on the fly signed by this CA.
// Clients must trust this CA for HTTPS to work without errors.
func WithProxyMitmCA(cert tls.Certificate) ServerOption {
	return func(s *Server) {
		s.mitmCA = &cert
	}
}

// WithClientKey sets the authorized client public key ("vt-pub-...").
// When set, only clients with the matching private key can connect.
func WithClientKey(pubKey string) ServerOption {
	return func(s *Server) {
		key, err := parsePublicKey(pubKey)
		if err != nil {
			panic(fmt.Sprintf("vtunnel: invalid client key: %v", err))
		}
		s.clientPubKey = key
	}
}

// NewServer creates a new vtunnel server.
func NewServer(opts ...ServerOption) *Server {
	s := &Server{
		keepAlive:   defaultKeepAlive,
		streamPool:  make(chan tunnelAssignment),
		listeners:   make(map[int]net.Listener),
		domainMap:   make(map[string]string),
		tlsUpstream: make(map[string]string),
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.clientPubKey == nil {
		log.Println("[vtunnel-server] WARNING: No client key configured. Authentication is DISABLED. Do NOT use in production! Use --client-key or VTUNNEL_CLIENT_KEY.")
	}
	return s
}

// HandleConn handles a WebSocket connection from a client.
// Runs h2c (HTTP/2 cleartext) over the WebSocket connection for stream multiplexing.
// Listeners persist across reconnections; acceptLoops keep running and
// wait for tunnel streams from the stream pool.
func (s *Server) HandleConn(wsConn *websocket.Conn) {
	conn := NewWSConn(wsConn)

	log.Println("[vtunnel-server] Client connected")

	h2s := &http2.Server{
		IdleTimeout: s.keepAlive * 2,
	}
	h2s.ServeConn(conn, &http2.ServeConnOpts{
		Handler: s.tunnelMux(),
	})

	log.Println("[vtunnel-server] Client disconnected")
}

// tunnelMux returns the HTTP handler routing for the h2mux connection.
func (s *Server) tunnelMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /listen", s.handleListenHTTP)
	mux.HandleFunc("POST /forward", s.handleForwardHTTP)
	mux.HandleFunc("POST /tunnel", s.handleTunnelHTTP)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	return s.authMiddleware(mux)
}

// authMiddleware validates the Authorization header on every request.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.clientPubKey != nil {
			if !validateAuthToken(r.Header.Get("Authorization"), s.clientPubKey) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// handleListenHTTP handles POST /listen — register a port forward.
func (s *Server) handleListenHTTP(w http.ResponseWriter, r *http.Request) {
	var req listenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, listenResponse{OK: false, Error: "invalid request body"})
		return
	}

	reply, err := s.handleListen(req)
	resp := listenResponse{OK: err == nil, Port: reply.Port, LocalAddr: reply.LocalAddr}
	if err != nil {
		resp.Error = err.Error()
	}
	writeJSON(w, resp)
}

// handleForwardHTTP handles POST /forward — register a domain forward.
// Functionally identical to /listen but named separately for clarity.
func (s *Server) handleForwardHTTP(w http.ResponseWriter, r *http.Request) {
	s.handleListenHTTP(w, r)
}

// handleTunnelHTTP handles POST /tunnel — long-polling tunnel stream.
// Blocks until a tunnel assignment is available or the connection dies.
func (s *Server) handleTunnelHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case a := <-s.streamPool:
		defer close(a.done)

		w.Header().Set("X-Tunnel-Port", strconv.Itoa(a.port))
		w.WriteHeader(http.StatusOK)
		http.NewResponseController(w).Flush()

		log.Printf("[vtunnel-server] New tunnel: port=%d", a.port)
		streamConn := newH2StreamConn(r.Body, w)
		pipe(streamConn, a.tcpConn)

	case <-r.Context().Done():
		return // h2 connection died
	}
}

// handleListen processes a listen request from the client.
//
// Two modes of operation:
//
//  1. Port-based (Listen): req.Port is set, req.Domain is empty.
//     Server opens the requested TCP port and tunnels all connections.
//
//  2. Domain-based (Forward): req.Port is 0, req.Domain is set.
//     Server auto-allocates a free port and registers a proxy domain mapping
//     so the HTTP/CONNECT proxy routes traffic for that domain through the tunnel.
//
// Listeners are persistent — they survive client reconnects. On reconnect
// the client replays its Listen/Forward calls; existing listeners are reused.
func (s *Server) handleListen(req listenRequest) (listenRequest, error) {
	port := req.Port

	s.listenersMu.Lock()
	// Reuse existing listener on reconnect (client replays its forwards).
	if port != 0 {
		if _, exists := s.listeners[port]; exists {
			s.listenersMu.Unlock()
			log.Printf("[vtunnel-server] Reusing listener on port %d", port)
			return listenRequest{}, nil
		}
	}

	// Port 0 = auto-allocate (used by Forward).
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.listenersMu.Unlock()
		log.Printf("[vtunnel-server] Failed to listen on %s: %v", addr, err)
		return listenRequest{}, err
	}

	if port == 0 {
		port = ln.Addr().(*net.TCPAddr).Port
	}

	s.listeners[port] = ln
	s.listenersMu.Unlock()

	log.Printf("[vtunnel-server] Listening on %s", ln.Addr())

	// Build reply with the allocated port.
	reply := listenRequest{Port: port}

	// Register domain mapping for proxy.
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	// When MITM is active and the client's target is a TLS endpoint (:443),
	// record the hostname so the proxy can do TLS through the tunnel itself
	// (controlling ALPN), instead of relying on client-side TLS.
	if req.Domain != "" && s.mitmCA != nil && !strings.HasPrefix(req.LocalAddr, "tls://") {
		if host, p, _ := net.SplitHostPort(req.LocalAddr); p == "443" {
			s.tlsUpstreamMu.Lock()
			s.tlsUpstream[target] = host
			s.tlsUpstreamMu.Unlock()
		}
	}
	if req.Domain != "" {
		_, _, err := net.SplitHostPort(req.Domain)
		if err != nil {
			// Domain without port — register for both :80 and :443.
			s.SetDomainMapping(net.JoinHostPort(req.Domain, "80"), target)
			s.SetDomainMapping(net.JoinHostPort(req.Domain, "443"), target)
		} else {
			s.SetDomainMapping(req.Domain, target)
		}
	}

	// Start persistent accept loop — runs forever, uses streamPool to
	// wait for tunnel streams.
	go s.acceptLoop(ln, port)

	return reply, nil
}

// tlsUpstreamHost returns the original hostname for a tunnel target
// that needs proxy-side TLS (e.g. "google.com" for target "127.0.0.1:54321").
func (s *Server) tlsUpstreamHost(target string) (string, bool) {
	s.tlsUpstreamMu.RLock()
	host, ok := s.tlsUpstream[target]
	s.tlsUpstreamMu.RUnlock()
	return host, ok
}

// acceptLoop accepts TCP connections and tunnels them through h2mux streams.
// It NEVER stops — when the client disconnects, handleTunnelConn blocks until
// a new tunnel stream arrives (with timeout).
func (s *Server) acceptLoop(ln net.Listener, port int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			// Listener was closed (server shutdown)
			log.Printf("[vtunnel-server] Accept error on port %d: %v", port, err)
			s.listenersMu.Lock()
			delete(s.listeners, port)
			s.listenersMu.Unlock()
			return
		}
		setTCPOptions(conn)
		go s.handleTunnelConn(conn, port)
	}
}

// handleTunnelConn pushes the TCP connection to the stream pool and waits for
// a tunnel stream from the client to pipe data through.
func (s *Server) handleTunnelConn(tcpConn net.Conn, port int) {
	defer tcpConn.Close()

	done := make(chan struct{})
	select {
	case s.streamPool <- tunnelAssignment{port: port, tcpConn: tcpConn, done: done}:
		<-done // wait for pipe to complete
	case <-time.After(streamWaitTimeout):
		log.Printf("[vtunnel-server] No stream for port %d (timeout)", port)
	}
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
