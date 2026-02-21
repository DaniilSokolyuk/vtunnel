package vtunnel

import (
	"encoding/json"
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

	// Active SSH connection
	activeConn   ssh.Conn
	activeConnMu sync.RWMutex
	connReady    chan struct{} // closed when activeConn becomes non-nil

	// Persistent listeners (survive reconnections)
	listeners   map[int]net.Listener
	listenersMu sync.Mutex

	// Proxy state (survives reconnections)
	domainMap     map[string]string
	domainMu      sync.RWMutex
	proxyListener net.Listener
	proxyDone     chan struct{}
	proxyOnce     sync.Once
}

// ServerOption configures a Server.
type ServerOption func(*Server)

// WithServerKeepAlive sets the keepalive ping interval for the server.
func WithServerKeepAlive(d time.Duration) ServerOption {
	return func(s *Server) {
		s.keepAlive = d
	}
}

// NewServer creates a new vtunnel server.
func NewServer(opts ...ServerOption) *Server {
	hostKey, err := generateHostKey()
	if err != nil {
		panic("vtunnel: generate host key: " + err.Error())
	}

	sshConfig := &ssh.ServerConfig{NoClientAuth: true}
	sshConfig.AddHostKey(hostKey)

	s := &Server{
		sshConfig: sshConfig,
		keepAlive: defaultKeepAlive,
		connReady: make(chan struct{}),
		listeners: make(map[int]net.Listener),
		domainMap: make(map[string]string),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// HandleConn handles a WebSocket connection from a client.
// Listeners persist across reconnections; acceptLoops keep running and
// use getSSH() to wait for the next connection.
func (s *Server) HandleConn(wsConn *websocket.Conn) {
	conn := newWSConn(wsConn)
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		log.Printf("[vtunnel-server] SSH handshake failed: %v", err)
		return
	}
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
// Listeners are persistent at the Server level and reused across reconnects.
func (s *Server) handleListen(_ ssh.Conn, r *ssh.Request) {
	var req listenRequest
	if err := json.Unmarshal(r.Payload, &req); err != nil {
		log.Printf("[vtunnel-server] Invalid listen request: %v", err)
		r.Reply(false, []byte("invalid payload"))
		return
	}

	s.listenersMu.Lock()
	_, exists := s.listeners[req.Port]
	if exists {
		s.listenersMu.Unlock()
		log.Printf("[vtunnel-server] Reusing listener on port %d", req.Port)
		r.Reply(true, nil)
		return
	}

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(req.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.listenersMu.Unlock()
		log.Printf("[vtunnel-server] Failed to listen on %s: %v", addr, err)
		r.Reply(false, []byte(err.Error()))
		return
	}

	s.listeners[req.Port] = ln
	s.listenersMu.Unlock()

	log.Printf("[vtunnel-server] Listening on %s", addr)
	r.Reply(true, nil)

	// Register domain mapping for proxy if localAddr specifies a non-loopback host
	if req.LocalAddr != "" {
		host, _, err := net.SplitHostPort(req.LocalAddr)
		if err == nil && host != "localhost" && host != "127.0.0.1" && host != "::1" {
			target := net.JoinHostPort("127.0.0.1", strconv.Itoa(req.Port))
			s.domainMu.Lock()
			s.domainMap[req.LocalAddr] = target
			s.domainMu.Unlock()
			log.Printf("[vtunnel-server] Proxy mapping: %s -> %s", req.LocalAddr, target)
		}
	}

	// Start persistent accept loop — runs forever, uses getSSH() to
	// wait for reconnects
	go s.acceptLoop(ln, req.Port)
}

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
