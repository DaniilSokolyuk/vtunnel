package vtunnel

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// bestDomainMatch picks the key of patterns that best matches hostPort.
//
// An exact key wins outright. Otherwise wildcard keys are considered with
// nginx-style semantics:
//   - `*.suffix:port`  (leftmost wildcard) matches one or more extra labels.
//   - `prefix.*:port`  (rightmost wildcard) matches one or more extra labels.
//   - `*` must be a complete label on a dot border; no `*` in the middle.
//
// Priority: exact > leftmost > rightmost; within a group, the longest pattern
// wins. Both the sandbox router and the controlplane proxy route through this,
// so a host resolves the same way on either side of a tunnel.
func bestDomainMatch[V any](patterns map[string]V, hostPort string) (string, bool) {
	if _, ok := patterns[hostPort]; ok {
		return hostPort, true
	}

	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return "", false
	}

	var bestPattern string
	var bestLeft bool
	for pattern := range patterns {
		isLeft, ok := wildcardMatches(pattern, host, port)
		if !ok {
			continue
		}
		if bestPattern == "" ||
			(isLeft && !bestLeft) ||
			(isLeft == bestLeft && len(pattern) > len(bestPattern)) {
			bestPattern = pattern
			bestLeft = isLeft
		}
	}
	return bestPattern, bestPattern != ""
}

// wildcardMatches reports whether a domain map key is a wildcard pattern
// that matches `host:port`. Returns (isLeftmost, matched).
func wildcardMatches(pattern, host, port string) (bool, bool) {
	patHost, patPort, err := net.SplitHostPort(pattern)
	if err != nil {
		return false, false
	}
	if patPort != port {
		return false, false
	}
	if strings.HasPrefix(patHost, "*.") {
		suffix := patHost[1:] // ".suffix"
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
			return true, true
		}
		return false, false
	}
	if strings.HasSuffix(patHost, ".*") {
		prefix := patHost[:len(patHost)-1] // "prefix."
		if strings.HasPrefix(host, prefix) && len(host) > len(prefix) {
			return false, true
		}
	}
	return false, false
}

// serveHijack handles HTTP/1.x CONNECT by hijacking the connection.
func serveHijack(w http.ResponseWriter, targetConn net.Conn) {
	clientConn, brw, err := hijack(w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	brw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	brw.Flush()

	// Flush any buffered data from the client
	if n := brw.Reader.Buffered(); n > 0 {
		buf, _ := brw.Peek(n)
		targetConn.Write(buf)
	}

	dualStream(targetConn, clientConn, clientConn)
}

// hijack takes over the underlying connection from the ResponseWriter.
func hijack(w http.ResponseWriter) (net.Conn, *bufio.ReadWriter, error) {
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return nil, nil, fmt.Errorf("hijack failed: %w", err)
	}
	return conn, brw, nil
}

// serveH2Connect handles HTTP/2+ CONNECT by streaming via ResponseWriter and Request.Body.
func serveH2Connect(w http.ResponseWriter, r *http.Request, targetConn net.Conn) {
	defer r.Body.Close()
	w.WriteHeader(http.StatusOK)
	if err := http.NewResponseController(w).Flush(); err != nil {
		return
	}
	dualStream(targetConn, r.Body, w)
}

// dualStream copies data bidirectionally between target and client.
func dualStream(target net.Conn, clientReader io.Reader, clientWriter io.Writer) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		flushingCopy(clientWriter, target)
		if cw, ok := clientWriter.(closeWriter); ok {
			cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		bufPtr := bufPool.Get().(*[]byte)
		buf := (*bufPtr)[:cap(*bufPtr)]
		io.CopyBuffer(target, clientReader, buf)
		bufPool.Put(bufPtr)
		if cw, ok := target.(closeWriter); ok {
			cw.CloseWrite()
		}
	}()
	wg.Wait()
}

type closeWriter interface {
	CloseWrite() error
}

// flushingCopy copies from src to dst, flushing after each write if dst supports it.
func flushingCopy(dst io.Writer, src io.Reader) {
	rw, isRW := dst.(http.ResponseWriter)
	bufPtr := bufPool.Get().(*[]byte)
	buf := (*bufPtr)[:cap(*bufPtr)]
	defer bufPool.Put(bufPtr)

	if !isRW {
		io.CopyBuffer(dst, src, buf)
		return
	}

	rc := http.NewResponseController(rw)
	for {
		nr, readErr := src.Read(buf)
		if nr > 0 {
			nw, writeErr := dst.Write(buf[:nr])
			if writeErr != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
			if nw != nr {
				return
			}
		}
		if readErr != nil {
			return
		}
	}
}

// forwardTrailers re-emits upstream response trailers (e.g. grpc-status)
// after the body has been copied. Trailer names are unknown until the body
// is drained, so they are sent unannounced via http.TrailerPrefix.
func forwardTrailers(w http.ResponseWriter, resp *http.Response) {
	for k, vv := range resp.Trailer {
		for _, v := range vv {
			w.Header().Set(http.TrailerPrefix+k, v)
		}
	}
}

var bufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 32*1024)
		return &buf
	},
}

// h2StreamConn wraps an HTTP/2 stream (Request.Body + ResponseWriter) as a net.Conn
// so that tls.Server can perform a TLS handshake over it.
type h2StreamConn struct {
	r  io.ReadCloser
	w  io.Writer
	rc *http.ResponseController
}

func newH2StreamConn(r io.ReadCloser, w http.ResponseWriter) *h2StreamConn {
	return &h2StreamConn{r: r, w: w, rc: http.NewResponseController(w)}
}

func (c *h2StreamConn) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *h2StreamConn) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if err != nil {
		return n, err
	}
	if err := c.rc.Flush(); err != nil {
		return n, err
	}
	return n, nil
}
func (c *h2StreamConn) Close() error         { return c.r.Close() }
func (c *h2StreamConn) LocalAddr() net.Addr  { return h2Addr{} }
func (c *h2StreamConn) RemoteAddr() net.Addr { return h2Addr{} }
func (c *h2StreamConn) SetDeadline(t time.Time) error {
	if err := c.rc.SetReadDeadline(t); err != nil {
		return err
	}
	return c.rc.SetWriteDeadline(t)
}
func (c *h2StreamConn) SetReadDeadline(t time.Time) error  { return c.rc.SetReadDeadline(t) }
func (c *h2StreamConn) SetWriteDeadline(t time.Time) error { return c.rc.SetWriteDeadline(t) }

type h2Addr struct{}

func (h2Addr) Network() string { return "h2" }
func (h2Addr) String() string  { return "h2-stream" }

// bufferedConn reads via a bufio.Reader first so bytes already buffered by
// net/http are not lost when the connection is handed over.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func newBufferedConn(c net.Conn, r *bufio.Reader) *bufferedConn {
	return &bufferedConn{Conn: c, r: r}
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// CloseWrite forwards TCP half-close to the wrapped conn, so dualStream's
// closeWriter assertion still fires through the buffered wrapper (the embedded
// net.Conn interface would otherwise hide the underlying *net.TCPConn's method).
func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// injectConfiguredHeaders overwrites headers on the forwarded request using
// values configured on the corresponding domain forward. Set-not-Add: the
// controlplane is authoritative, so any value the sandbox application sent
// for the same name is replaced. A nil inject map is a no-op.
func injectConfiguredHeaders(dst, inject http.Header) {
	for name, values := range inject {
		dst[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
	}
}

func removeHopByHop(h http.Header, preserveTeTrailers bool) {
	for _, key := range strings.Split(h.Get("Connection"), ",") {
		h.Del(strings.TrimSpace(key))
	}
	for _, key := range hopByHopHeaders {
		h.Del(key)
	}

	if preserveTeTrailers && hasOnlyTrailersToken(h.Values("Te")) {
		h.Set("Te", "trailers")
		return
	}
	h.Del("Te")
}

func hasOnlyTrailersToken(values []string) bool {
	if len(values) == 0 {
		return false
	}

	for _, v := range values {
		for _, token := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "trailers") {
				continue
			}
			return false
		}
	}

	return true
}
