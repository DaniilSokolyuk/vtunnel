package vtunnel

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
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
		keepAlive:   defaultKeepAlive,
		connReady:   make(chan struct{}),
		listeners:   make(map[int]net.Listener),
		domainMap:   make(map[string]string),
		tlsUpstream: make(map[string]string),
	}
	for _, opt := range opts {
		opt(s)
	}

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
			r.Reply(true, nil)
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

	// Start persistent accept loop — runs forever, uses getSSH() to
	// wait for reconnects.
	go s.acceptLoop(ln, port)
}

// tlsUpstreamHost returns the original hostname for a tunnel target
// that needs proxy-side TLS (e.g. "google.com" for target "127.0.0.1:54321").
func (s *Server) tlsUpstreamHost(target string) (string, bool) {
	s.tlsUpstreamMu.RLock()
	host, ok := s.tlsUpstream[target]
	s.tlsUpstreamMu.RUnlock()
	return host, ok
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
