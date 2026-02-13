package vtunnel

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// Server handles reverse tunnel connections from clients
type Server struct {
	conn         *websocket.Conn
	listeners    map[int]net.Listener
	streams      map[uint32]net.Conn
	streamID     uint32
	mu           sync.RWMutex
	writeMu      sync.Mutex
	done         chan struct{}
	readDeadline time.Duration
}

// NewServer creates a new vtunnel server
func NewServer() *Server {
	return &Server{
		listeners:    make(map[int]net.Listener),
		streams:      make(map[uint32]net.Conn),
		done:         make(chan struct{}),
		readDeadline: defaultPingInterval * 2,
	}
}

// HandleConn handles a WebSocket connection from a client
func (s *Server) HandleConn(conn *websocket.Conn) {
	s.conn = conn
	reason := "shutdown"
	defer func() { s.cleanup(reason) }()

	log.Println("[vtunnel-server] Client connected")

	// Set up keepalive read deadline
	if s.readDeadline > 0 {
		_ = s.conn.SetReadDeadline(time.Now().Add(s.readDeadline))
	}

	for {
		select {
		case <-s.done:
			reason = "server_done"
			return
		default:
		}

		_, data, err := conn.ReadMessage()
		if err != nil {
			if closeErr, ok := err.(*websocket.CloseError); ok {
				reason = fmt.Sprintf("peer_close code=%d text=%s", closeErr.Code, closeErr.Text)
				log.Printf("[vtunnel-server] Close error: code=%d text=%q", closeErr.Code, closeErr.Text)
			} else if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				reason = fmt.Sprintf("read_error %v", err)
				log.Printf("[vtunnel-server] Read error: %v", err)
			} else {
				reason = fmt.Sprintf("read_end %v", err)
			}
			return
		}
		if s.readDeadline > 0 {
			_ = s.conn.SetReadDeadline(time.Now().Add(s.readDeadline))
		}

		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			log.Printf("[vtunnel-server] Invalid message: %v", err)
			continue
		}

		switch msg.Type {
		case MsgPing:
			s.sendMessage(Message{Type: MsgPong})
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
	s.mu.RLock()
	_, exists := s.listeners[port]
	s.mu.RUnlock()
	if exists {
		s.sendMessage(Message{Type: MsgListenOK, Port: port})
		return
	}

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[vtunnel-server] Failed to listen on %s: %v", addr, err)
		s.sendMessage(Message{Type: MsgListenErr, Port: port, Error: err.Error()})
		return
	}

	s.mu.Lock()
	s.listeners[port] = ln
	s.mu.Unlock()

	log.Printf("[vtunnel-server] Listening on %s", addr)
	s.sendMessage(Message{Type: MsgListenOK, Port: port})

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
func (s *Server) cleanup(reason string) {
	close(s.done)

	s.mu.Lock()
	defer s.mu.Unlock()

	log.Printf("[vtunnel-server] Cleanup: reason=%s", reason)
	s.closeConn(websocket.CloseGoingAway, wsCloseReason(reason))
	for _, ln := range s.listeners {
		ln.Close()
	}
	for _, conn := range s.streams {
		conn.Close()
	}

	log.Println("[vtunnel-server] Cleanup complete")
}

func (s *Server) closeConn(code int, reason string) {
	if s.conn == nil {
		return
	}
	deadline := time.Now().Add(defaultCloseWriteWait)
	s.writeMu.Lock()
	err := s.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), deadline)
	s.writeMu.Unlock()
	if err != nil {
		log.Printf("[vtunnel-server] Close write error: %v", err)
	}
	_ = s.conn.Close()
}

func wsCloseReason(reason string) string {
	reason = strings.ReplaceAll(reason, "\n", " ")
	reason = strings.ReplaceAll(reason, "\r", " ")
	if len(reason) > 120 {
		reason = reason[:120]
	}
	return reason
}
