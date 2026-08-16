package vtunnel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

const (
	defaultKeepAlive = 30 * time.Second
	sshWaitTimeout   = 35 * time.Second
)

// Server handles reverse tunnel connections from clients over SSH-over-WebSocket.
type Server struct {
	sshConfig *ssh.ServerConfig
	keepAlive time.Duration

	// Client authentication
	clientPubKey ssh.PublicKey // nil = no auth

	// Active SSH connection
	activeConn   ssh.Conn
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

// WithClientKey sets the authorized client public key ("vt-pub-...").
// When set, only clients with the matching private key can connect.
// The server host key is deterministically derived from this key,
// enabling automatic MITM protection on the client side.
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
		keepAlive: defaultKeepAlive,
		connReady: make(chan struct{}),
		listeners: make(map[int]net.Listener),
	}
	for _, opt := range opts {
		opt(s)
	}

	s.router = newRouter()

	// Build SSH config after options are applied
	var hostKey ssh.Signer
	var err error
	if s.clientPubKey != nil {
		hostKey, err = deriveHostKey(s.clientPubKey)
	} else {
		hostKey, err = generateHostKey()
	}
	if err != nil {
		panic("vtunnel: generate host key: " + err.Error())
	}

	sshConfig := &ssh.ServerConfig{}
	sshConfig.AddHostKey(hostKey)

	if s.clientPubKey != nil {
		expected := s.clientPubKey.Marshal()
		sshConfig.PublicKeyCallback = func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), expected) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unauthorized key")
		}
	} else {
		sshConfig.NoClientAuth = true
		log.Println("[vtunnel-server] WARNING: No client key configured. Authentication is DISABLED. Do NOT use in production! Use --client-key or VTUNNEL_CLIENT_KEY.")
	}

	s.sshConfig = sshConfig
	return s
}

// HandleConn handles a WebSocket connection from a client.
// Listeners persist across reconnections; acceptLoops keep running and
// use getSSH() to wait for the next connection.
func (s *Server) HandleConn(wsConn *websocket.Conn) {
	conn := NewWSConn(wsConn)
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		log.Printf("[vtunnel-server] SSH handshake failed: %v", err)
		return
	}
	conn.SetDeadline(time.Time{}) // clear deadline after handshake
	defer sshConn.Close()

	log.Println("[vtunnel-server] Client connected")

	// Publish this connection so acceptLoops (and new ones) can use it
	s.setSSH(sshConn)
	defer func() {
		s.clearSSH(sshConn)
		log.Println("[vtunnel-server] Client disconnected")
	}()

	go s.handleRequests(sshConn, reqs)
	go rejectChannels(chans)
	if s.keepAlive > 0 {
		go keepAliveLoop(sshConn, s.keepAlive)
	}

	// Block until SSH connection dies
	sshConn.Wait()
}

// setSSH publishes a new SSH connection and unblocks anyone waiting in getSSH.
func (s *Server) setSSH(conn ssh.Conn) {
	s.activeConnMu.Lock()
	s.activeConn = conn
	ch := s.connReady
	s.connReady = make(chan struct{}) // prepare for next wait cycle
	s.activeConnMu.Unlock()
	close(ch) // unblock all goroutines waiting in getSSH
}

// clearSSH marks the connection as dead and creates a new wait channel.
func (s *Server) clearSSH(conn ssh.Conn) {
	s.activeConnMu.Lock()
	if s.activeConn == conn {
		s.activeConn = nil
		s.connReady = make(chan struct{}) // new channel for next wait
	}
	s.activeConnMu.Unlock()
}

// getSSH returns the current SSH connection. If none is active, it blocks
// until one becomes available or the timeout expires.
func (s *Server) getSSH() ssh.Conn {
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
	case <-time.After(sshWaitTimeout):
		log.Printf("[vtunnel-server] getSSH timeout (%v)", sshWaitTimeout)
		return nil
	}
}

// handleRequests processes SSH global requests from the client.
func (s *Server) handleRequests(sshConn ssh.Conn, reqs <-chan *ssh.Request) {
	for r := range reqs {
		switch r.Type {
		case "ping":
			r.Reply(true, []byte("pong"))
		case "listen":
			s.handleListen(sshConn, r)
		default:
			if r.WantReply {
				r.Reply(false, nil)
			}
		}
	}
}

// handleListen processes a listen request from the client.
//
// Two modes of operation:
//
//  1. Port-based (Listen): req.Port is set, req.Domains is empty.
//     Server opens the requested TCP port and tunnels all connections.
//
//  2. Router-based (Forward): req.Port is 0, req.Domains lists the domains the
//     controlplane proxy handles. The server allocates a port and points the
//     router at it, so allowlisted requests are chained through the tunnel.
//
// Listeners are persistent — they survive client reconnects. On reconnect the
// client replays its calls; an existing listener is reused and its routes are
// refreshed from the request.
//
// The request carries domain names only. Targets, credentials and injected
// headers stay on the controlplane and never cross the tunnel.
func (s *Server) handleListen(_ ssh.Conn, r *ssh.Request) {
	var req listenRequest
	if err := json.Unmarshal(r.Payload, &req); err != nil {
		log.Printf("[vtunnel-server] Invalid listen request: %v", err)
		r.Reply(false, []byte("invalid payload"))
		return
	}

	port := req.Port

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
			if len(req.Domains) > 0 {
				s.router.SetRoutes(port, req.Domains)
			}
			r.Reply(true, marshalJSON(listenRequest{Port: port}))
			return
		}
	}

	// Port 0 = auto-allocate (used by Forward).
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.listenersMu.Unlock()
		log.Printf("[vtunnel-server] Failed to listen on %s: %v", addr, err)
		r.Reply(false, []byte(err.Error()))
		return
	}

	if port == 0 {
		port = ln.Addr().(*net.TCPAddr).Port
	}

	s.listeners[port] = ln
	s.listenersMu.Unlock()

	log.Printf("[vtunnel-server] Listening on %s", ln.Addr())

	// Reply with the allocated port (no LocalAddr rewrite — client dials plain TCP).
	reply := listenRequest{Port: port}
	r.Reply(true, marshalJSON(reply))

	// Point the router at this tunnel port for the client's domains.
	s.router.SetRoutes(port, req.Domains)

	// Start persistent accept loop — runs forever, uses getSSH() to
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

// acceptLoop accepts TCP connections and tunnels them through SSH channels.
// It NEVER stops — when SSH dies, handleTunnelConn calls getSSH() which
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

// handleTunnelConn gets the current SSH connection (waiting for reconnect
// if needed), then opens a channel and pipes data.
func (s *Server) handleTunnelConn(tcpConn net.Conn, port int) {
	defer tcpConn.Close()

	sshConn := s.getSSH()
	if sshConn == nil {
		log.Printf("[vtunnel-server] No SSH connection for port %d (timeout)", port)
		return
	}

	payload := marshalJSON(tunnelRequest{Port: port})
	ch, reqs, err := sshConn.OpenChannel("tunnel", payload)
	if err != nil {
		log.Printf("[vtunnel-server] OpenChannel failed for port %d: %v", port, err)
		return
	}
	go ssh.DiscardRequests(reqs)

	log.Printf("[vtunnel-server] New tunnel: port=%d", port)
	pipe(ch, tcpConn)
}
