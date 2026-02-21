package vtunnel

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

const defaultKeepAlive = 30 * time.Second

// Server handles reverse tunnel connections from clients over SSH-over-WebSocket.
type Server struct {
	sshConfig *ssh.ServerConfig
	keepAlive time.Duration

	// Proxy state (survives reconnections)
	domainMap     map[string]string
	domainMu      sync.RWMutex
	proxyListener net.Listener
	proxyDone     chan struct{}
	proxyOnce     sync.Once
}

// ServerOption configures a Server.
type ServerOption func(*Server)

// WithKeepAlive sets the keepalive ping interval for the server.
// Zero or negative disables keepalive.
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
		domainMap: make(map[string]string),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// HandleConn handles a WebSocket connection from a client.
// All per-connection state is local; concurrent calls are safe.
func (s *Server) HandleConn(wsConn *websocket.Conn) {
	conn := newWSConn(wsConn)
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		log.Printf("[vtunnel-server] SSH handshake failed: %v", err)
		return
	}
	defer sshConn.Close()

	log.Println("[vtunnel-server] Client connected")

	// Per-connection state — local, no shared mutable state
	listeners := make(map[int]net.Listener)
	var mu sync.Mutex
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer func() {
		mu.Lock()
		for port, ln := range listeners {
			ln.Close()
			log.Printf("[vtunnel-server] Closed listener on port %d", port)
		}
		mu.Unlock()
		log.Println("[vtunnel-server] Client disconnected")
	}()

	go s.handleRequests(ctx, sshConn, reqs, listeners, &mu)
	go rejectChannels(chans)
	if s.keepAlive > 0 {
		go keepAliveLoop(sshConn, s.keepAlive)
	}

	// Block until SSH connection dies
	sshConn.Wait()
}

// handleRequests processes SSH global requests from the client.
func (s *Server) handleRequests(ctx context.Context, sshConn ssh.Conn, reqs <-chan *ssh.Request, listeners map[int]net.Listener, mu *sync.Mutex) {
	for r := range reqs {
		switch r.Type {
		case "ping":
			r.Reply(true, []byte("pong"))
		case "listen":
			s.handleListen(ctx, sshConn, r, listeners, mu)
		default:
			if r.WantReply {
				r.Reply(false, nil)
			}
		}
	}
}

// handleListen processes a listen request from the client.
func (s *Server) handleListen(ctx context.Context, sshConn ssh.Conn, r *ssh.Request, listeners map[int]net.Listener, mu *sync.Mutex) {
	var req listenRequest
	if err := json.Unmarshal(r.Payload, &req); err != nil {
		log.Printf("[vtunnel-server] Invalid listen request: %v", err)
		r.Reply(false, []byte("invalid payload"))
		return
	}

	mu.Lock()
	if _, exists := listeners[req.Port]; exists {
		mu.Unlock()
		r.Reply(true, nil)
		return
	}
	mu.Unlock()

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(req.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[vtunnel-server] Failed to listen on %s: %v", addr, err)
		r.Reply(false, []byte(err.Error()))
		return
	}

	mu.Lock()
	listeners[req.Port] = ln
	mu.Unlock()

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

	go s.acceptLoop(ctx, sshConn, ln, req.Port)
}

// acceptLoop accepts TCP connections and tunnels them through SSH channels.
func (s *Server) acceptLoop(ctx context.Context, sshConn ssh.Conn, ln net.Listener, port int) {
	// Close listener when context is cancelled (HandleConn exiting)
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	var tempDelay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if tempDelay == 0 {
				tempDelay = 5 * time.Millisecond
			} else {
				tempDelay *= 2
			}
			if tempDelay > 1*time.Second {
				tempDelay = 1 * time.Second
			}
			log.Printf("[vtunnel-server] Accept error on port %d (retrying in %v): %v", port, tempDelay, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(tempDelay):
			}
			continue
		}
		tempDelay = 0
		setTCPOptions(conn)

		go s.handleTunnelConn(sshConn, conn, port)
	}
}

// handleTunnelConn opens an SSH channel to the client and pipes data.
func (s *Server) handleTunnelConn(sshConn ssh.Conn, tcpConn net.Conn, port int) {
	defer tcpConn.Close()

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
