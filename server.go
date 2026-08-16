package vtunnel

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/vivid-money/vtunnel/internal/session"
	"github.com/vivid-money/vtunnel/internal/tunnelkey"
)

const (
	defaultKeepAlive   = 30 * time.Second
	sessionWaitTimeout = 35 * time.Second
)

// Server is the sandbox end of the tunnel. It accepts a connection from a
// client, opens the ports the client asks for, and hands every connection to
// those ports back through the tunnel.
type Server struct {
	keepAlive    time.Duration
	protocol     Protocol
	streamWindow int

	// keys authenticates both ends; nil means the tunnel is unauthenticated.
	keys *tunnelkey.Keys

	// Active session
	activeConn   session.Session
	activeConnMu sync.RWMutex
	connReady    chan struct{} // closed when activeConn becomes non-nil

	// Persistent listeners (survive reconnections)
	listeners map[int]net.Listener
	// routerPorts records which of those ports were opened to carry domains, so
	// an empty domain list can be told apart from a plain port forward that
	// never had any. Without it the two are indistinguishable and one of them
	// has to be guessed wrong: either a port forward clears the whole allowlist,
	// or withdrawing the last forward is impossible.
	routerPorts map[int]bool
	listenersMu sync.Mutex

	// closed is set once, by Close. It is atomic rather than guarded because
	// every stage of accepting a client consults it — the handshake that is
	// still running when Close lands must not end up publishing its session.
	closed atomic.Bool

	// router is the sandbox-side forward proxy. Its allowlist survives
	// reconnections; the client replays it on every connect.
	router *Router
}

// ServerOption configures a Server.
type ServerOption func(*Server)

// WithServerKeepAlive sets the keepalive ping interval for the server.
func WithServerKeepAlive(d time.Duration) ServerOption {
	return func(s *Server) {
		s.keepAlive = d
	}
}

// WithServerProtocol picks the session protocol this server speaks. The client
// must be configured with the same one through [WithProtocol]; see [Protocol].
func WithServerProtocol(p Protocol) ServerOption {
	return func(s *Server) {
		s.protocol = p
	}
}

// WithServerStreamWindow sets how much the controlplane may send into one
// tunnelled connection before this sandbox has acknowledged any of it. Zero
// keeps the default of 8 MB.
//
// It is [WithStreamWindow] for the other direction, and everything said there
// about what it costs and when to raise it applies here too.
func WithServerStreamWindow(bytes int) ServerOption {
	return func(s *Server) {
		s.streamWindow = bytes
	}
}

// WithServerSecret sets the tunnel secret, the one value that authenticates
// this server and the client to each other. The client must be given the same
// secret through [WithSecret].
//
// Any string will do; see [WithSecret] for what that means and what gets
// warned about. It is a secret here too, so pass it at launch — an environment
// variable set by whatever creates the sandbox — and never bake it into an
// image. Anyone holding it can be either end.
//
// An empty secret leaves the tunnel unauthenticated, and [NewServer] says so.
func WithServerSecret(secret string) ServerOption {
	return func(s *Server) {
		if secret == "" {
			return
		}
		if w := tunnelkey.Warning(secret); w != "" {
			log.Printf("[vtunnel-server] WARNING: %s.", w)
		}
		keys, err := tunnelkey.Derive(secret)
		if err != nil {
			panic(fmt.Sprintf("vtunnel: derive tunnel keys: %v", err))
		}
		s.keys = keys
	}
}

// NewServer creates a new vtunnel server.
func NewServer(opts ...ServerOption) *Server {
	s := &Server{
		keepAlive:   defaultKeepAlive,
		connReady:   make(chan struct{}),
		listeners:   make(map[int]net.Listener),
		routerPorts: make(map[int]bool),
	}
	for _, opt := range opts {
		opt(s)
	}

	s.router = newRouter()

	if s.protocol.insecure() {
		log.Printf("[vtunnel-server] WARNING: protocol %q has no encryption and no authentication. "+
			"Any secret configured is ignored, and anyone who can reach this port owns the tunnel. "+
			"It is here to be measured against, not to be run.", s.protocol)
	} else if s.keys == nil {
		log.Println("[vtunnel-server] WARNING: No tunnel secret configured. Authentication is DISABLED. Do NOT use in production! Use --secret or VTUNNEL_SECRET.")
	}
	return s
}

// HandleWebSocket serves a client that arrived over a WebSocket. It is
// [Server.HandleConn] with the gorilla connection adapted, and the shape most
// deployments want:
//
//	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
//	    conn, err := upgrader.Upgrade(w, r, nil)
//	    if err != nil {
//	        return
//	    }
//	    defer conn.Close()
//	    server.HandleWebSocket(conn)
//	})
func (s *Server) HandleWebSocket(wsConn *websocket.Conn) {
	s.HandleConn(NewWSConn(wsConn))
}

// HandleConn serves a client over an established connection, and returns when
// that connection ends.
//
// Any net.Conn will do — a WebSocket, plain TCP, TLS, anything that carries
// bytes in order. The tunnel's security does not depend on which: the session
// authenticates both ends itself.
//
// Listeners persist across reconnections; their accept loops keep running and
// wait for the next connection.
func (s *Server) HandleConn(conn net.Conn) {
	sess, err := session.Serve(session.Kind(s.protocol), conn, session.Config{
		Keys:         s.keys,
		Handshake:    defaultHandshakeTimeout,
		StreamWindow: s.streamWindow,
	})
	if err != nil {
		log.Printf("[vtunnel-server] Handshake failed: %v", err)
		return
	}
	defer sess.Close()

	log.Println("[vtunnel-server] Client connected")

	// Publish this session so acceptLoops (and new ones) can use it
	if !s.setSession(sess) {
		log.Println("[vtunnel-server] Refusing a client: the server is closed")
		return
	}
	defer func() {
		s.clearSession(sess)
		log.Println("[vtunnel-server] Client disconnected")
	}()

	go serveStreams(sess, s.handleStream)
	if s.keepAlive > 0 {
		go keepAliveLoop(sess, s.keepAlive)
	}

	sess.Wait()
}

// setSession publishes a new session and unblocks anyone waiting in getSession.
// It reports whether the session was taken; a closed server takes none.
//
// The check comes after publishing as well as before. Close cannot see a
// session that is still being handshaked, so without the second look a client
// arriving at exactly the wrong moment would be served by a server that had
// already shut down — with an accept loop feeding it ports that no longer
// exist.
func (s *Server) setSession(sess session.Session) bool {
	if s.closed.Load() {
		return false
	}

	s.activeConnMu.Lock()
	displaced := s.activeConn
	s.activeConn = sess
	ch := s.connReady
	s.connReady = make(chan struct{}) // prepare for next wait cycle
	s.activeConnMu.Unlock()
	close(ch) // unblock all goroutines waiting in getSession

	// One client at a time, and the newcomer wins. Refusing instead would lock
	// a client out of its own sandbox after a half-open connection — nothing
	// notices those until the keepalive does, and until then the ghost would
	// hold the tunnel. What must not happen is both being served: the old
	// session used to stay up, with its streams answered by a server that had
	// moved on, and its accept loops feeding a client nobody was reading.
	if displaced != nil {
		log.Println("[vtunnel-server] A second client took the tunnel over; closing the previous session")
		displaced.Close()
	}

	if s.closed.Load() {
		s.clearSession(sess)
		return false
	}
	return true
}

// clearSession marks the session as dead and creates a new wait channel.
func (s *Server) clearSession(sess session.Session) {
	s.activeConnMu.Lock()
	if s.activeConn == sess {
		s.activeConn = nil
		s.connReady = make(chan struct{}) // new channel for next wait
	}
	s.activeConnMu.Unlock()
}

// getSession returns the current session. If none is active, it blocks until
// one becomes available or the timeout expires.
func (s *Server) getSession() session.Session {
	s.activeConnMu.RLock()
	c := s.activeConn
	ready := s.connReady
	s.activeConnMu.RUnlock()

	if c != nil {
		return c
	}

	// Wait for reconnect
	select {
	case <-ready:
		s.activeConnMu.RLock()
		c = s.activeConn
		s.activeConnMu.RUnlock()
		return c
	case <-time.After(sessionWaitTimeout):
		log.Printf("[vtunnel-server] getSession timeout (%v)", sessionWaitTimeout)
		return nil
	}
}

// handleStream dispatches a stream the client opened. Ping is already
// answered by serveStreams; the sandbox has nothing else to offer.
func (s *Server) handleStream(stream net.Conn, h streamHeader) {
	defer stream.Close()

	if h.Type != streamListen {
		log.Printf("[vtunnel-server] Unknown stream type %q", h.Type)
		writeFrame(stream, streamReply{Error: "unknown stream type"})
		return
	}
	s.handleListen(stream, h)
}

// handleListen processes a listen request from the client.
//
// Two modes of operation:
//
//  1. Port-based (Listen): h.Port is set, h.Domains is empty.
//     Server opens the requested TCP port and tunnels all connections.
//
//  2. Router-based (Forward): h.Port is 0, h.Domains lists the domains the
//     controlplane proxy handles. The server allocates a port and points the
//     router at it, so allowlisted requests are chained through the tunnel.
//
// Listeners are persistent — they survive client reconnects. On reconnect the
// client replays its calls; an existing listener is reused and its routes are
// refreshed from the request.
func (s *Server) handleListen(stream net.Conn, h streamHeader) {
	port := h.Port

	if s.closed.Load() {
		writeFrame(stream, streamReply{Error: "server is closed"})
		return
	}

	s.listenersMu.Lock()
	// Reuse existing listener on reconnect (client replays its forwards).
	if port != 0 {
		if _, exists := s.listeners[port]; exists {
			log.Printf("[vtunnel-server] Reusing listener on port %d", port)
			// Routes are refreshed on reuse — the client is authoritative and
			// may have added or dropped domains since it last connected —
			// including down to none, which is how the last forward is
			// withdrawn. A plain port forward sends no domains and never had
			// any, and clearing on its behalf would send every forwarded domain
			// straight out of the sandbox, quietly; routerPorts is what tells
			// the two apart.
			if len(h.Domains) > 0 || s.routerPorts[port] {
				s.routerPorts[port] = true
				s.listenersMu.Unlock()
				s.router.SetRoutes(port, h.Domains)
			} else {
				s.listenersMu.Unlock()
			}
			writeFrame(stream, streamReply{OK: true, Port: port})
			return
		}
	}

	// Port 0 = auto-allocate (used by Forward).
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.listenersMu.Unlock()
		log.Printf("[vtunnel-server] Failed to listen on %s: %v", addr, err)
		writeFrame(stream, streamReply{Error: err.Error()})
		return
	}

	if port == 0 {
		port = ln.Addr().(*net.TCPAddr).Port
	}

	s.listeners[port] = ln
	if len(h.Domains) > 0 {
		s.routerPorts[port] = true
	}
	s.listenersMu.Unlock()

	log.Printf("[vtunnel-server] Listening on %s", ln.Addr())

	// Routes first, answer second. The answer is what starts the client, and
	// between the two an application in the sandbox could ask for a domain
	// whose route was promised but not yet installed — which the router does
	// not treat as an error, it treats it as direct egress, past the tunnel and
	// past the credential.
	s.router.SetRoutes(port, h.Domains)

	// Reply with the allocated port (no LocalAddr rewrite — client dials plain TCP).
	writeFrame(stream, streamReply{OK: true, Port: port})

	// Start persistent accept loop — runs forever, uses getSession() to
	// wait for reconnects.
	go s.acceptLoop(ln, port)
}

// Close releases everything the server owns: every forwarded port and its
// accept loop, the routing proxy, and the client session currently being
// served. It is safe to call more than once, and safe to call while
// [Server.HandleConn] is still running — that call returns as its session ends.
//
// Forwarded ports deliberately outlive any one client connection, so that a
// reconnecting client finds them still open. That makes this the only way to
// get rid of them: without it an embedding process leaks a listener, a
// goroutine and a descriptor per forward, still answering on behalf of a tunnel
// nobody is watching.
//
// A closed server stays closed; further listen requests are refused.
func (s *Server) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}

	s.listenersMu.Lock()
	listeners := make([]net.Listener, 0, len(s.listeners))
	for port, ln := range s.listeners {
		listeners = append(listeners, ln)
		delete(s.listeners, port)
	}
	clear(s.routerPorts)
	s.listenersMu.Unlock()

	// Each close ends one acceptLoop, which is what removes the goroutine.
	for _, ln := range listeners {
		ln.Close()
	}

	s.router.Close()

	s.activeConnMu.Lock()
	sess := s.activeConn
	s.activeConn = nil
	s.activeConnMu.Unlock()
	if sess != nil {
		sess.Close()
	}
	return nil
}

// Router returns the sandbox-side forward proxy. Its allowlist survives client
// reconnections.
func (s *Server) Router() *Router { return s.router }

// StartProxy starts the router on addr.
func (s *Server) StartProxy(addr string) error { return s.router.Start(addr) }

// CloseProxy stops the router.
func (s *Server) CloseProxy() { s.router.Close() }

// acceptLoop accepts TCP connections and tunnels them through session streams.
// It NEVER stops — when the session dies, handleTunnelConn calls getSession()
// which blocks until the client reconnects.
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

// handleTunnelConn gets the current session (waiting for reconnect if needed),
// then opens a stream and pipes data.
func (s *Server) handleTunnelConn(tcpConn net.Conn, port int) {
	defer tcpConn.Close()

	sess := s.getSession()
	if sess == nil {
		log.Printf("[vtunnel-server] No session for port %d (timeout)", port)
		return
	}

	stream, err := openTunnel(sess, port)
	if err != nil {
		log.Printf("[vtunnel-server] Open stream failed for port %d: %v", port, err)
		return
	}

	log.Printf("[vtunnel-server] New tunnel: port=%d", port)
	pipe(stream, tcpConn)
}
