package vtunnel

import (
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

const (
	defaultKeepAlive = 15 * time.Second
	sessionWaitTimeout = 35 * time.Second
)

// Server handles reverse tunnel connections from clients over yamux-over-WebSocket.
type Server struct {
	keepAlive time.Duration

	// Client authentication
	clientPubKey ed25519.PublicKey // nil = no auth

	// Active yamux session
	activeSession *yamux.Session
	activeConnMu  sync.RWMutex
	connReady     chan struct{} // closed when activeSession becomes non-nil

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
		connReady:   make(chan struct{}),
		listeners:   make(map[int]net.Listener),
		domainMap:   make(map[string]string),
		tlsUpstream: make(map[string]string),
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.clientPubKey == nil {
		log.Println("[vtunnel-server] WARNING: No client key configured. Authentication is DISABLED.")
	}
	return s
}

// HandleConn handles a WebSocket connection from a client.
// Listeners persist across reconnections; acceptLoops keep running and
// use getSession() to wait for the next connection.
func (s *Server) HandleConn(wsConn *websocket.Conn) {
	conn := NewWSConn(wsConn)
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// 1. Custom auth handshake
	if err := serverHandshake(conn, s.clientPubKey); err != nil {
		log.Printf("[vtunnel-server] Handshake failed: %v", err)
		return
	}
	conn.SetDeadline(time.Time{}) // clear deadline after handshake

	// 2. Create yamux server session
	cfg := s.yamuxConfig()
	session, err := yamux.Server(conn, cfg)
	if err != nil {
		log.Printf("[vtunnel-server] yamux session failed: %v", err)
		return
	}
	defer session.Close()

	log.Println("[vtunnel-server] Client connected")

	// Publish this session so acceptLoops (and new ones) can use it
	s.setSession(session)
	defer func() {
		s.clearSession(session)
		log.Println("[vtunnel-server] Client disconnected")
	}()

	// 3. Accept control stream (first stream from client)
	ctrlStream, err := session.AcceptStream()
	if err != nil {
		log.Printf("[vtunnel-server] Accept control stream failed: %v", err)
		return
	}
	go s.handleControlStream(ctrlStream)

	// 4. Block until session dies
	<-session.CloseChan()
}

// yamuxConfig returns the yamux configuration for the server.
func (s *Server) yamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.MaxStreamWindowSize = 16 * 1024 * 1024
	cfg.ConnectionWriteTimeout = 10 * time.Second
	cfg.StreamOpenTimeout = 10 * time.Second
	cfg.LogOutput = io.Discard
	if s.keepAlive > 0 {
		cfg.EnableKeepAlive = true
		cfg.KeepAliveInterval = s.keepAlive
		// Adapt write timeout so keepalive pings time out promptly
		if t := s.keepAlive * 3; t < cfg.ConnectionWriteTimeout {
			cfg.ConnectionWriteTimeout = t
		}
	} else {
		cfg.EnableKeepAlive = false
	}
	return cfg
}

// setSession publishes a new yamux session and unblocks anyone waiting in getSession.
func (s *Server) setSession(session *yamux.Session) {
	s.activeConnMu.Lock()
	s.activeSession = session
	ch := s.connReady
	s.connReady = make(chan struct{}) // prepare for next wait cycle
	s.activeConnMu.Unlock()
	close(ch) // unblock all goroutines waiting in getSession
}

// clearSession marks the session as dead and creates a new wait channel.
func (s *Server) clearSession(session *yamux.Session) {
	s.activeConnMu.Lock()
	if s.activeSession == session {
		s.activeSession = nil
		s.connReady = make(chan struct{}) // new channel for next wait
	}
	s.activeConnMu.Unlock()
}

// getSession returns the current yamux session. If none is active, it blocks
// until one becomes available or the timeout expires.
func (s *Server) getSession() *yamux.Session {
	s.activeConnMu.RLock()
	session := s.activeSession
	ready := s.connReady
	s.activeConnMu.RUnlock()

	if session != nil {
		return session
	}

	// Wait for reconnect
	select {
	case <-ready:
		s.activeConnMu.RLock()
		session = s.activeSession
		s.activeConnMu.RUnlock()
		return session
	case <-time.After(sessionWaitTimeout):
		log.Printf("[vtunnel-server] getSession timeout (%v)", sessionWaitTimeout)
		return nil
	}
}

// handleControlStream processes control requests from the client on the control stream.
func (s *Server) handleControlStream(stream *yamux.Stream) {
	defer stream.Close()
	for {
		var req controlRequest
		if err := readMsg(stream, &req); err != nil {
			return // stream/session closed
		}
		switch req.Type {
		case "listen":
			reply, err := s.handleListen(req.listenRequest)
			resp := controlResponse{ID: req.ID, OK: err == nil, listenRequest: reply}
			if err != nil {
				resp.Error = err.Error()
			}
			if err := writeMsg(stream, resp); err != nil {
				return
			}
		default:
			writeMsg(stream, controlResponse{ID: req.ID, OK: false, Error: "unknown request type"})
		}
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
//
// MITM + TLS targets: when the MITM CA is configured and the client's target
// address (LocalAddr) has port 443, the server rewrites LocalAddr in the reply
// to add a "tls://" prefix. This tells the client to establish TLS to the target,
// so the MITM proxy can send decrypted plain HTTP through the tunnel while the
// client re-encrypts it for the upstream server. Without MITM, the proxy does
// a raw TCP passthrough and the client dials plain TCP (browser TLS goes end-to-end).
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

	// Start persistent accept loop — runs forever, uses getSession() to
	// wait for reconnects.
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

// acceptLoop accepts TCP connections and tunnels them through yamux streams.
// It NEVER stops — when the session dies, handleTunnelConn calls getSession() which
// blocks until the client reconnects.
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

// handleTunnelConn gets the current yamux session (waiting for reconnect
// if needed), then opens a stream and pipes data.
func (s *Server) handleTunnelConn(tcpConn net.Conn, port int) {
	defer tcpConn.Close()

	session := s.getSession()
	if session == nil {
		log.Printf("[vtunnel-server] No session for port %d (timeout)", port)
		return
	}

	stream, err := session.OpenStream()
	if err != nil {
		log.Printf("[vtunnel-server] Open stream failed for port %d: %v", port, err)
		return
	}
	defer stream.Close()

	// Write tunnel header
	if err := writeMsg(stream, tunnelRequest{Port: port}); err != nil {
		log.Printf("[vtunnel-server] Write tunnel header failed: %v", err)
		return
	}

	log.Printf("[vtunnel-server] New tunnel: port=%d", port)
	pipe(stream, tcpConn)
}
