package vtunnel

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/gorilla/websocket"
)

// Server handles reverse tunnel connections from clients
type Server struct {
	conn      *websocket.Conn
	listeners map[int]net.Listener
	streams   map[uint32]net.Conn
	streamID  uint32
	mu        sync.RWMutex
	writeMu   sync.Mutex
	done      chan struct{}
}

// NewServer creates a new vtunnel server
func NewServer() *Server {
	return &Server{
		listeners: make(map[int]net.Listener),
		streams:   make(map[uint32]net.Conn),
		done:      make(chan struct{}),
	}
}

// HandleConn handles a WebSocket connection from a client
func (s *Server) HandleConn(conn *websocket.Conn) {
	s.conn = conn
	defer s.cleanup()

	log.Println("[vtunnel-server] Client connected")

	// Set up keepalive - reset deadline when client pings us
	s.conn.SetPingHandler(nil)

	for {
		select {
		case <-s.done:
			return
		default:
		}

		_, data, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("[vtunnel-server] Read error: %v", err)
			}
			return
		}

		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			log.Printf("[vtunnel-server] Invalid message: %v", err)
			continue
		}

		switch msg.Type {
		case MsgListen:
			s.handleListen(msg.Port)
		case MsgData:
			s.handleData(msg.StreamID, msg.Data)
		case MsgClose:
			s.handleClose(msg.StreamID)
		}
	}
}

// handleListen starts listening on a port
func (s *Server) handleListen(port int) {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[vtunnel-server] Failed to listen on %s: %v", addr, err)
		return
	}

	s.mu.Lock()
	s.listeners[port] = ln
	s.mu.Unlock()

	log.Printf("[vtunnel-server] Listening on %s", addr)

	go s.acceptLoop(ln, port)
}

// acceptLoop accepts connections on a listener
func (s *Server) acceptLoop(ln net.Listener, port int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				log.Printf("[vtunnel-server] Accept error on port %d: %v", port, err)
				return
			}
		}

		streamID := atomic.AddUint32(&s.streamID, 1)

		s.mu.Lock()
		s.streams[streamID] = conn
		s.mu.Unlock()

		log.Printf("[vtunnel-server] New connection: stream=%d, port=%d", streamID, port)

		// Notify client about new connection
		s.sendMessage(Message{
			Type:     MsgConnect,
			StreamID: streamID,
			Port:     port,
		})

		// Start reading from TCP and forwarding to WebSocket
		go s.forwardToClient(streamID, conn)
	}
}

// forwardToClient reads from TCP connection and sends to WebSocket
func (s *Server) forwardToClient(streamID uint32, conn net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("[vtunnel-server] Read error on stream %d: %v", streamID, err)
			}
			s.sendMessage(Message{Type: MsgClose, StreamID: streamID})
			s.removeStream(streamID)
			return
		}

		s.sendMessage(Message{
			Type:     MsgData,
			StreamID: streamID,
			Data:     buf[:n],
		})
	}
}

// handleData forwards data from client to TCP connection
func (s *Server) handleData(streamID uint32, data []byte) {
	s.mu.RLock()
	conn, ok := s.streams[streamID]
	s.mu.RUnlock()

	if !ok {
		return
	}

	if _, err := conn.Write(data); err != nil {
		log.Printf("[vtunnel-server] Write error on stream %d: %v", streamID, err)
		s.removeStream(streamID)
	}
}

// handleClose closes a stream
func (s *Server) handleClose(streamID uint32) {
	s.removeStream(streamID)
}

// removeStream removes and closes a stream
func (s *Server) removeStream(streamID uint32) {
	s.mu.Lock()
	conn, ok := s.streams[streamID]
	if ok {
		delete(s.streams, streamID)
	}
	s.mu.Unlock()

	if ok && conn != nil {
		conn.Close()
	}
}

// sendMessage sends a message to the client
func (s *Server) sendMessage(msg Message) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("[vtunnel-server] Marshal error: %v", err)
		return
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if err := s.conn.WriteMessage(websocket.TextMessage, data); err != nil {
		log.Printf("[vtunnel-server] Write error: %v", err)
	}
}

// cleanup closes all resources
func (s *Server) cleanup() {
	close(s.done)

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, ln := range s.listeners {
		ln.Close()
	}
	for _, conn := range s.streams {
		conn.Close()
	}

	log.Println("[vtunnel-server] Cleanup complete")
}
