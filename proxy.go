package vtunnel

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	proxyDialTimeout    = 10 * time.Second
	proxyIOTimeout      = 60 * time.Second
	proxyIdleTimeout    = 5 * time.Minute
	proxyMaxHeaderBytes = 8192
)

func (s *Server) SetDomainMapping(domain, target string) {
	s.domainMu.Lock()
	s.domainMap[domain] = target
	s.domainMu.Unlock()
	log.Printf("[vtunnel-proxy] Domain mapping added: %s -> %s", domain, target)
}

func (s *Server) RemoveDomainMapping(domain string) {
	s.domainMu.Lock()
	delete(s.domainMap, domain)
	s.domainMu.Unlock()
	log.Printf("[vtunnel-proxy] Domain mapping removed: %s", domain)
}

func (s *Server) resolveDomain(domain string) (string, bool) {
	s.domainMu.RLock()
	target, ok := s.domainMap[domain]
	s.domainMu.RUnlock()
	return target, ok
}

func (s *Server) StartProxy(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("proxy listen on %s: %w", addr, err)
	}

	s.proxyListener = ln
	s.proxyDone = make(chan struct{})
	s.proxyOnce = sync.Once{} // reset for potential re-use

	log.Printf("[vtunnel-proxy] Listening on %s", addr)

	go s.proxyAcceptLoop()
	return nil
}

func (s *Server) CloseProxy() {
	s.proxyOnce.Do(func() {
		if s.proxyDone != nil {
			close(s.proxyDone)
		}
		if s.proxyListener != nil {
			s.proxyListener.Close()
		}
	})
}

func (s *Server) proxyAcceptLoop() {
	defer s.proxyListener.Close()

	for {
		conn, err := s.proxyListener.Accept()
		if err != nil {
			select {
			case <-s.proxyDone:
				log.Printf("[vtunnel-proxy] Listener closed (shutdown)")
				return
			default:
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				log.Printf("[vtunnel-proxy] Accept error: %v", err)
				return
			}
		}

		go s.handleProxyConn(conn)
	}
}

func (s *Server) handleProxyConn(conn net.Conn) {
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(proxyIOTimeout))

	br := bufio.NewReaderSize(conn, proxyMaxHeaderBytes)

	req, err := http.ReadRequest(br)
	if err != nil {
		log.Printf("[vtunnel-proxy] Failed to read request: %v", err)
		return
	}

	if req.Method == http.MethodConnect {
		s.handleConnect(conn, br, req)
	} else {
		s.handlePlainHTTP(conn, req)
	}
}

func (s *Server) handleConnect(clientConn net.Conn, br *bufio.Reader, req *http.Request) {
	targetAddr := req.Host
	if targetAddr == "" {
		targetAddr = req.URL.Host
	}

	if _, _, err := net.SplitHostPort(targetAddr); err != nil {
		targetAddr = net.JoinHostPort(targetAddr, "443")
	}

	dialAddr := targetAddr
	if mapped, ok := s.resolveDomain(targetAddr); ok {
		log.Printf("[vtunnel-proxy] CONNECT %s -> mapped to %s", targetAddr, mapped)
		dialAddr = mapped
	} else {
		log.Printf("[vtunnel-proxy] CONNECT %s -> direct", targetAddr)
	}

	upstream, err := net.DialTimeout("tcp", dialAddr, proxyDialTimeout)
	if err != nil {
		log.Printf("[vtunnel-proxy] CONNECT dial %s failed: %v", dialAddr, err)
		fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer upstream.Close()

	setTCPOptions(upstream)

	_, err = fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if err != nil {
		log.Printf("[vtunnel-proxy] CONNECT write 200 failed: %v", err)
		return
	}

	if br.Buffered() > 0 {
		buffered, _ := br.Peek(br.Buffered())
		if len(buffered) > 0 {
			if _, err := upstream.Write(buffered); err != nil {
				log.Printf("[vtunnel-proxy] CONNECT flush buffered data failed: %v", err)
				return
			}
			br.Discard(len(buffered))
		}
	}

	clientConn.SetDeadline(time.Time{})
	upstream.SetDeadline(time.Time{})

	bridgeConns(clientConn, upstream, br)
}

func (s *Server) handlePlainHTTP(clientConn net.Conn, req *http.Request) {
	targetHost := req.URL.Host
	if targetHost == "" {
		targetHost = req.Host
	}
	if targetHost == "" {
		log.Printf("[vtunnel-proxy] Plain HTTP request with no host")
		fmt.Fprintf(clientConn, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}

	host, port, err := net.SplitHostPort(targetHost)
	if err != nil {
		host = targetHost
		port = "80"
		targetHost = net.JoinHostPort(host, port)
	}

	dialAddr := targetHost
	if mapped, ok := s.resolveDomain(targetHost); ok {
		log.Printf("[vtunnel-proxy] HTTP %s %s -> mapped to %s", req.Method, targetHost, mapped)
		dialAddr = mapped
		req.Host = host
	} else {
		log.Printf("[vtunnel-proxy] HTTP %s %s -> direct", req.Method, targetHost)
	}

	req.URL.Scheme = ""
	req.URL.Host = ""
	req.RequestURI = req.URL.RequestURI()

	removeHopByHopHeaders(req.Header)

	upstream, err := net.DialTimeout("tcp", dialAddr, proxyDialTimeout)
	if err != nil {
		log.Printf("[vtunnel-proxy] HTTP dial %s failed: %v", dialAddr, err)
		fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer upstream.Close()

	setTCPOptions(upstream)

	if err := req.Write(upstream); err != nil {
		log.Printf("[vtunnel-proxy] HTTP write request to %s failed: %v", dialAddr, err)
		fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}

	upstreamBr := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(upstreamBr, req)
	if err != nil {
		log.Printf("[vtunnel-proxy] HTTP read response from %s failed: %v", dialAddr, err)
		fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer resp.Body.Close()

	removeHopByHopHeaders(resp.Header)

	if err := resp.Write(clientConn); err != nil {
		log.Printf("[vtunnel-proxy] HTTP write response to client failed: %v", err)
	}
}

func bridgeConns(client net.Conn, upstream net.Conn, clientReader *bufio.Reader) {
	idle := proxyIdleTimeout

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			client.SetReadDeadline(time.Now().Add(idle))
			n, err := clientReader.Read(buf)
			if n > 0 {
				upstream.SetWriteDeadline(time.Now().Add(idle))
				if _, wErr := upstream.Write(buf[:n]); wErr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		if tc, ok := upstream.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			upstream.SetReadDeadline(time.Now().Add(idle))
			n, err := upstream.Read(buf)
			if n > 0 {
				client.SetWriteDeadline(time.Now().Add(idle))
				if _, wErr := client.Write(buf[:n]); wErr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		if tc, ok := client.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
}

var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopByHopHeaders(h http.Header) {
	for _, connHeader := range h["Connection"] {
		for _, name := range strings.Split(connHeader, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				h.Del(name)
			}
		}
	}

	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}
