package vtunnel

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
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
	listeners   map[int]net.Listener
	listenersMu sync.Mutex

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
// keeps the default of 256 KB.
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
		keepAlive: defaultKeepAlive,
		connReady: make(chan struct{}),
		listeners: make(map[int]net.Listener),
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
	s.setSession(sess)
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
func (s *Server) setSession(sess session.Session) {
	s.activeConnMu.Lock()
	s.activeConn = sess
	ch := s.connReady
	s.connReady = make(chan struct{}) // prepare for next wait cycle
	s.activeConnMu.Unlock()
	close(ch) // unblock all goroutines waiting in getSession
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

	s.listenersMu.Lock()
	// Reuse existing listener on reconnect (client replays its forwards).
	if port != 0 {
		if _, exists := s.listeners[port]; exists {
			s.listenersMu.Unlock()
			log.Printf("[vtunnel-server] Reusing listener on port %d", port)
			// Routes are refreshed on reuse — the client is authoritative and
			// may have added or dropped domains since it last connected — but
			// only when the request carries any. A plain port forward sends no
			// domains, and if its ephemeral port ever collided with the router's
			// this would clear the whole allowlist and send every forwarded
			// domain straight out of the sandbox, quietly.
			if len(h.Domains) > 0 {
				s.router.SetRoutes(port, h.Domains)
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
	s.listenersMu.Unlock()

	log.Printf("[vtunnel-server] Listening on %s", ln.Addr())

	// Reply with the allocated port (no LocalAddr rewrite — client dials plain TCP).
	writeFrame(stream, streamReply{OK: true, Port: port})

	// Point the router at this tunnel port for the client's domains.
	s.router.SetRoutes(port, h.Domains)

	// Start persistent accept loop — runs forever, uses getSession() to
	// wait for reconnects.
	go s.acceptLoop(ln, port)
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
