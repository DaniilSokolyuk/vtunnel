package vtunnel

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/idna"
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
//
// Matching is case-insensitive, as hostnames are (RFC 4343). Comparing them
// byte for byte meant a single capital letter missed the allowlist: on the
// controlplane that fails closed, but on the sandbox router a miss is dialled
// directly, so `https://API.corp/` egressed from the sandbox without ever
// meeting the tunnel, the proxy or its injected credential.
func bestDomainMatch[V any](patterns map[string]V, hostPort string) (string, bool) {
	if _, ok := patterns[hostPort]; ok {
		return hostPort, true
	}

	canonical, ok := canonicalHostPort(hostPort)
	if !ok {
		return "", false
	}
	host, port, err := net.SplitHostPort(canonical)
	if err != nil {
		return "", false
	}

	var bestPattern string
	var bestLeft bool
	for pattern := range patterns {
		canonicalPattern, ok := canonicalHostPort(pattern)
		if !ok {
			continue
		}
		if canonicalPattern == canonical {
			return pattern, true // the same name, spelled differently
		}
		isLeft, ok := wildcardMatches(canonicalPattern, host, port)
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

// canonicalHostPort rewrites an authority into the one spelling route tables
// are keyed by, so that every way of writing a name resolves to the same route.
// It reports false for an authority with no host to speak of, which must never
// be treated as a match: an empty host is a dialable address in Go, and it
// means the local machine.
//
// This is what keeps the allowlist honest. A miss fails closed on the
// controlplane but fails open on the sandbox router, where it is dialled
// directly — past the tunnel, past interception and past the injected
// credential. Every spelling that reaches the same server therefore has to
// reach the same route, or the allowlist is one keystroke wide.
func canonicalHostPort(hostPort string) (string, bool) {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return "", false
	}
	host = canonicalHost(host)
	if host == "" {
		return "", false
	}
	return net.JoinHostPort(host, canonicalPort(port)), true
}

// canonicalHost folds the spellings of a hostname that all reach the same
// server: letter case (RFC 4343), the trailing dot of a fully qualified name,
// and unicode, which every IDNA-aware client puts on the wire as punycode
// however it was configured.
func canonicalHost(host string) string {
	host = strings.ToLower(host)
	host = strings.TrimSuffix(host, ".")
	if strings.Trim(host, ".") == "" {
		return ""
	}
	if isASCII(host) {
		return host
	}
	// Punycode only: this has to survive the `*` of a wildcard pattern, which
	// the stricter lookup profile rejects as an invalid hostname.
	if ascii, err := idna.ToASCII(host); err == nil {
		return ascii
	}
	return host
}

// canonicalPort folds the zero padding net.Dial ignores: ":0443" reaches port
// 443, so it must not be a different route from ":443". Anything that is not a
// plain number — a service name — is left as written.
func canonicalPort(port string) string {
	trimmed := strings.TrimLeft(port, "0")
	if trimmed == "" {
		return port
	}
	for i := range len(trimmed) {
		if trimmed[i] < '0' || trimmed[i] > '9' {
			return port
		}
	}
	return trimmed
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// isRoutableAuthority reports whether hostPort names somewhere a client could
// actually be asking to reach.
//
// The authority of a CONNECT is written by the client, and on the sandbox side
// the client is the untrusted party. It is matched against the route table and
// is the key under which anything learned about the connection is stored, so an
// authority that is not a name is one that can be aimed at more than one route:
// `CONNECT *.corp:443` matched the key a `*.corp` route is stored under exactly,
// and everything learned from that connection then sat where the ordinary
// wildcard lookup finds it for every domain underneath.
func isRoutableAuthority(hostPort string) bool {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil || port == "" {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	return isHostname(host)
}

// isHostname reports whether s is a hostname rather than merely a string.
//
// A little wider than the letter of RFC 1123: underscores turn up in real
// service-discovery names, and a single trailing dot is how a fully qualified
// name is written. Non-ASCII is refused rather than guessed at — an IDNA-aware
// client sends punycode, which is ASCII, and canonicalHost converts the rest.
func isHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return false
	}
	for label := range strings.SplitSeq(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			switch c := label[i]; {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			case c == '-' || c == '_':
			default:
				return false
			}
		}
	}
	return true
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
//
// track registers the hijacked connection with whoever needs to be able to end
// it: net/http stops managing a connection the moment it is hijacked, so a
// server shutdown cannot reach this one. It may be nil.
func serveHijack(w http.ResponseWriter, targetConn net.Conn, track func(io.Closer) func()) {
	clientConn, brw, err := hijack(w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	if track != nil {
		defer track(clientConn)()
	}

	brw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	brw.Flush()

	// Whatever the client wrote after its request headers is the tunnel's
	// first bytes — except for the blank lines some of them pad with, which
	// would arrive at the target in front of everything else.
	discardConnectPadding(brw.Reader)

	// Flush any buffered data from the client
	if n := brw.Reader.Buffered(); n > 0 {
		buf, _ := brw.Peek(n)
		targetConn.Write(buf)
	}

	dualStream(targetConn, clientConn, clientConn)
}

// maxConnectPadding bounds how many stray line endings are skipped after a
// CONNECT. A handful covers what clients actually send; a limit is what keeps
// this from reading a payload that happens to start with blank lines.
const maxConnectPadding = 4

// discardConnectPadding drops the CRLFs some clients write after the CONNECT
// headers.
//
// RFC 9112 §2.2 lets a recipient ignore them, and clients do send them
// (mitmproxy fixed the same thing from a bug report). Left in place they become
// the first bytes of the tunnel: on the interception path the ClientHello no
// longer looks like TLS, so the connection is quietly piped instead of
// intercepted — no decryption, no injected credential — and on the piping path
// they arrive at the upstream in front of the ClientHello and break its
// handshake.
//
// Only what is already buffered is examined. Peeking further would wait, and
// the whole point is that the next thing may be a ClientHello nobody has sent
// yet.
//
// Telling padding from payload is the other half. A tunnel that goes on to
// carry something recognisable — a TLS record, the h2c preface, a request line
// — cannot have meant those blank lines, so they go. A tunnel whose next bytes
// are none of those is about to be piped through untouched, and there the
// blank lines may be the payload's own first bytes, so they stay. When nothing
// follows them yet there is nothing to go on, and a client that writes a blank
// line and then waits is the padding case the bug report described.
func discardConnectPadding(br *bufio.Reader) {
	padding := 0
	for padding < 2*maxConnectPadding && br.Buffered() >= padding+2 {
		head, err := br.Peek(padding + 2)
		if err != nil || string(head[padding:]) != "\r\n" {
			break
		}
		padding += 2
	}
	if padding == 0 {
		return
	}

	if following := br.Buffered() - padding; following > 0 {
		head, err := br.Peek(padding + min(following, connectPaddingLookahead))
		if err != nil || !startsLikeTunnelledHTTP(head[padding:]) {
			return
		}
	}
	br.Discard(padding)
}

// connectPaddingLookahead is how far past the padding discardConnectPadding
// looks to decide what it is looking at. A TLS record header is three bytes and
// the longest method this needs to recognise is shorter than that; the rest is
// slack.
const connectPaddingLookahead = 8

// startsLikeTunnelledHTTP reports whether b opens something this proxy would
// terminate rather than pipe. It is deliberately loose — it runs only to decide
// whether blank lines in front of b were padding, and b is a prefix that may
// still be growing.
func startsLikeTunnelledHTTP(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if startsLikeTLSRecord(b) {
		return true
	}
	if strings.HasPrefix(http2.ClientPreface, string(b)) || bytes.HasPrefix(b, []byte(http2.ClientPreface)) {
		return true
	}
	// Or a request line, by the same rule the tunnel classification uses.
	return couldBeRequestLine(b)
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

		// The error matters, not just whether the method exists. bufferedConn
		// implements CloseWrite unconditionally and can only forward it when
		// what it wraps is half-closable — over an HTTP/2 stream it used to
		// report success having done nothing, and the fallback below, the only
		// thing that would deliver EOF, was skipped.
		if cw, ok := clientWriter.(closeWriter); ok {
			if err := cw.CloseWrite(); err == nil {
				return
			}
		}
		// An HTTP/2 CONNECT tunnel has no half-close: the response stream ends
		// only when the handler returns, and the handler is still blocked on
		// the other direction. Closing the request body unblocks it so the
		// handler can return — which is what finally delivers EOF to the
		// client. Without this the upstream can close and the client hangs.
		if rc, ok := clientReader.(io.Closer); ok {
			rc.Close()
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
//
// It reports the error that ended the copy only when that error came from src
// and was not a clean end of body. Treating io.ErrUnexpectedEOF, a reset
// connection or an h2 RST_STREAM as end-of-body handed the client a truncated
// body inside a perfectly well-formed response, which is the one failure the
// caller has no other way to discover. A write error means the client is
// already gone, so there is nobody left to tell.
func flushingCopy(dst io.Writer, src io.Reader) error {
	rw, isRW := dst.(http.ResponseWriter)
	bufPtr := bufPool.Get().(*[]byte)
	buf := (*bufPtr)[:cap(*bufPtr)]
	defer bufPool.Put(bufPtr)

	if !isRW {
		_, err := io.CopyBuffer(dst, src, buf)
		return err
	}

	rc := http.NewResponseController(rw)
	for {
		nr, readErr := src.Read(buf)
		if nr > 0 {
			nw, writeErr := dst.Write(buf[:nr])
			if writeErr != nil {
				return nil
			}
			if err := rc.Flush(); err != nil {
				return nil
			}
			if nw != nr {
				return nil
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

// copyResponse writes an upstream response back to the client: headers, status,
// body and trailers. Both proxies end their plain-HTTP path here so streaming
// behaviour cannot drift between them.
//
// flushingCopy preserves event-by-event delivery for streaming responses
// (text/event-stream from LLM proxies, gRPC-web, long-poll endpoints). Plain
// io.Copy leaves the http.ResponseWriter's bufio buffer un-flushed between
// writes, batching SSE events into one chunk at end-of-body.
func copyResponse(w http.ResponseWriter, resp *http.Response) {
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	removeHopByHop(w.Header(), false)

	// Alt-Svc offers the client another way to the same origin, over HTTP/3 —
	// which is UDP, which this proxy neither terminates nor routes. A client
	// that takes the offer leaves the tunnel altogether: no interception, no
	// injected credential, no error to notice. mitmproxy rewrites the header to
	// point at itself and describes keeping it as something that "may cause
	// clients to bypass the proxy"; with no h3 listener to point at, dropping it
	// is the only honest answer. Whether the sandbox may speak UDP at all is a
	// firewall's business, not a proxy's.
	w.Header().Del("Alt-Svc")

	// Announced after the hop-by-hop sweep, not before: Trailer is itself
	// hop-by-hop, so an announcement written earlier is deleted by the sweep and
	// never reaches the client. Announcing lets a client read the names from
	// Trailer up front, the way the HTTP/2 mapping of gRPC expects.
	announced := make(map[string]bool, len(resp.Trailer))
	for k := range resp.Trailer {
		w.Header().Add("Trailer", k)
		announced[http.CanonicalHeaderKey(k)] = true
	}
	if len(resp.Trailer) > 0 {
		// A declared length and a trailer cannot coexist over HTTP/1.1: net/http
		// picks identity framing whenever it knows the length, and identity has
		// nowhere to put a trailer, so the announcement above would be the only
		// thing the client ever saw of it. HTTP/2 has no chunked encoding at all,
		// so an h2 upstream legitimately sends both and this is the ordinary case
		// for a gRPC response forwarded to an HTTP/1.1 client.
		w.Header().Del("Content-Length")
	}

	w.WriteHeader(resp.StatusCode)
	// The head is knowable now; the first body byte may be a minute away. A
	// streaming answer — a model thinking before its first token, a long poll,
	// an idle event stream — arrives head first and body later, and net/http
	// buffers the head until something flushes it, so the client saw nothing at
	// all and its response-header timeout fired on a request that was being
	// served correctly. A failed flush means the client is gone, which the copy
	// below discovers on its own write.
	_ = http.NewResponseController(w).Flush()

	copyErr := flushingCopy(w, resp.Body)
	forwardTrailers(w, resp, announced)

	if copyErr != nil {
		// The status line and part of the body are already on the wire, so there
		// is no status left to report this with. Killing the connection is the
		// only in-band signal a truncated body has: net/http recognises
		// ErrAbortHandler and drops it without logging a panic. Returning
		// normally instead would frame the fragment as a complete response and
		// the client would cache or commit it.
		log.Printf("[vtunnel-proxy] upstream body ended early: %v", copyErr)
		panic(http.ErrAbortHandler)
	}
}

// forwardTrailers re-emits upstream response trailers (grpc-status and the
// like) once the body has been copied, since their values are unknown until it
// is drained.
//
// A name that was announced is set plainly; one that only appeared while the
// body streamed was never declared, and the sole way to send it is unannounced
// via http.TrailerPrefix.
//
// Repeated values are kept. Setting each one in turn replaced the last, so a
// trailer sent more than once — repeated grpc-metadata-* or X-Trace entries are
// ordinary — arrived with everything but its final value dropped.
func forwardTrailers(w http.ResponseWriter, resp *http.Response, announced map[string]bool) {
	for k, vv := range resp.Trailer {
		name := k
		if !announced[http.CanonicalHeaderKey(k)] {
			name = http.TrailerPrefix + k
		}
		for i, v := range vv {
			if i == 0 {
				w.Header().Set(name, v)
				continue
			}
			w.Header().Add(name, v)
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
//
// It reports an error rather than nil when the wrapped connection cannot
// half-close — an HTTP/2 stream, for one. Claiming success there told
// dualStream the shutdown had been delivered when nothing had happened, and the
// peer waited for an EOF that was never coming.
func (c *bufferedConn) CloseWrite() error {
	cw, ok := c.Conn.(closeWriter)
	if !ok {
		return fmt.Errorf("half-close unsupported by %T", c.Conn)
	}
	return cw.CloseWrite()
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
func injectConfiguredHeaders(r *http.Request, inject http.Header) {
	for name, values := range inject {
		switch key := http.CanonicalHeaderKey(name); key {
		case "Cookie":
			// Cookie is additive in the protocol and singular on the wire: RFC
			// 6265 §5.4 allows at most one Cookie line, with the pairs joined
			// by "; ". Assigning it like any other header wrote one line per
			// configured value and threw away whatever cookies the application
			// was already carrying — there is no way to add a cookie by
			// replacing the jar.
			r.Header.Set(key, mergeCookies(r.Header.Values(key), values))

		case "Host":
			// net/http keeps the Host in a field of its own and ignores the
			// header map, so this used to do nothing at all, silently — and a
			// route pointed at a virtual-hosted internal target had no way to
			// name the vhost. Set after the authority check, which reads what
			// the client claimed, so nothing here widens what the sandbox may
			// aim a credential at.
			if len(values) > 0 {
				r.Host = values[len(values)-1]
				if r.URL != nil {
					r.URL.Host = r.Host
				}
			}

		default:
			r.Header[key] = append([]string(nil), values...)
		}
	}
}

// mergeCookies folds cookie pairs from several header lines into the one line
// the protocol allows, keeping the client's own pairs in front of the injected
// ones.
func mergeCookies(existing, injected []string) string {
	var pairs []string
	for _, line := range append(append([]string(nil), existing...), injected...) {
		for pair := range strings.SplitSeq(line, ";") {
			if pair = strings.TrimSpace(pair); pair != "" {
				pairs = append(pairs, pair)
			}
		}
	}
	return strings.Join(pairs, "; ")
}

// isUpgradeRequest reports whether r asks to switch protocols — a WebSocket
// handshake, or anything else carried by the same mechanism. Both halves matter:
// Upgrade names the protocol, and the Connection token is what makes it a
// request rather than an advertisement.
func isUpgradeRequest(r *http.Request) bool {
	if r.Header.Get("Upgrade") == "" {
		return false
	}
	return headerHasToken(r.Header, "Connection", "upgrade")
}

// headerHasToken reports whether a comma-separated header contains a token,
// case-insensitively and across repeated header lines.
func headerHasToken(h http.Header, name, token string) bool {
	for _, value := range h.Values(name) {
		for _, candidate := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(candidate), token) {
				return true
			}
		}
	}
	return false
}

// removeHopByHopForUpgrade strips what a proxy must not forward while keeping
// what carries the upgrade itself.
//
// Connection and Upgrade are hop-by-hop, and removeHopByHop deletes them — which
// is right for an ordinary request and fatal for this one. A proxy performing an
// upgrade is the hop those headers address, so dropping them turns a WebSocket
// handshake into a plain GET that the upstream answers 200 to, and the client
// waits for a 101 that is never coming.
//
// Everything named in Connection other than the upgrade token still goes, since
// those really are for this hop alone.
func removeHopByHopForUpgrade(h http.Header) {
	for _, value := range h.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			token = strings.TrimSpace(token)
			if token == "" || strings.EqualFold(token, "upgrade") {
				continue
			}
			h.Del(token)
		}
	}
	for _, key := range hopByHopHeaders {
		if key == "Connection" || key == "Upgrade" {
			continue
		}
		h.Del(key)
	}
	h.Del("Te")

	// Rewritten rather than passed along: the original may have listed tokens
	// that have just been removed.
	h.Set("Connection", "Upgrade")
}

// serveUpgrade completes a protocol upgrade over an already-dialled upstream.
//
// The handshake is re-issued as an ordinary request, so headers configured for
// the route land inside it — which is the whole reason this is not simply a byte
// pipe from the start. Once the upstream answers 101 the two connections are
// spliced and nothing further is parsed, so subprotocols, extensions and frame
// boundaries survive exactly as the endpoints negotiated them. Terminating the
// WebSocket instead, the way go-mitmproxy does with gorilla, would silently drop
// permessage-deflate and reassemble fragmented messages.
//
// The upstream answer is read before the client connection is touched: while w
// is still an ordinary ResponseWriter a failure can be reported as a status, and
// after the hijack it cannot. track may be nil; when set it registers the
// connections a shutdown has to be able to reach.
func serveUpgrade(w http.ResponseWriter, r *http.Request, upstream net.Conn, proxyForm bool, track func(io.Closer) func()) {
	upstream.SetDeadline(time.Now().Add(dialTimeout))

	write := r.Write
	if proxyForm {
		// The next hop is itself a proxy, so it needs the absolute form it
		// would have received from the client directly.
		write = r.WriteProxy
	}
	// Both failures below are logged rather than returned. On the controlplane
	// this answer travels back through the tunnel, and a socket error names the
	// internal address it was talking to — which is the one thing that is not
	// supposed to reach the sandbox.
	if err := write(upstream); err != nil {
		log.Printf("[vtunnel-proxy] upgrade %s: write to upstream failed: %v", r.Host, err)
		http.Error(w, "vtunnel: upstream connection failed", http.StatusBadGateway)
		return
	}

	br := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(br, r)
	if err != nil {
		log.Printf("[vtunnel-proxy] upgrade %s: read upstream response failed: %v", r.Host, err)
		http.Error(w, "vtunnel: upstream connection failed", http.StatusBadGateway)
		return
	}
	upstream.SetDeadline(time.Time{})

	if resp.StatusCode != http.StatusSwitchingProtocols {
		// The upstream declined to upgrade. That is an ordinary response and the
		// client is still expecting one, so nothing is hijacked.
		defer resp.Body.Close()
		copyResponse(w, resp)
		return
	}

	client, brw, err := hijack(w)
	if err != nil {
		log.Printf("[vtunnel-proxy] upgrade %s: hijack failed: %v", r.Host, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer client.Close()
	if track != nil {
		defer track(client)()
	}

	if err := resp.Write(brw); err != nil {
		log.Printf("[vtunnel-proxy] upgrade %s: write 101 failed: %v", r.Host, err)
		return
	}
	if err := brw.Flush(); err != nil {
		log.Printf("[vtunnel-proxy] upgrade %s: flush 101 failed: %v", r.Host, err)
		return
	}

	// Both sides may already hold buffered bytes: the upstream's reader can have
	// frames that arrived with the 101, and net/http may have read ahead on the
	// client. Splicing the raw sockets would drop them.
	clientConn := newBufferedConn(client, brw.Reader)
	dualStream(newBufferedConn(upstream, br), clientConn, clientConn)
}

func removeHopByHop(h http.Header, isRequest bool) {
	// Values, not Get: Connection may arrive as several header lines, and
	// reading only the first forwarded everything named on the rest to the next
	// hop. removeHopByHopForUpgrade already reads them all.
	for _, value := range h.Values("Connection") {
		for _, key := range strings.Split(value, ",") {
			h.Del(strings.TrimSpace(key))
		}
	}
	for _, key := range hopByHopHeaders {
		h.Del(key)
	}

	// TE is hop-by-hop, so it has to be re-stated rather than passed on — but
	// "trailers" is the one token that is not about this hop at all. It is how a
	// client tells the origin that trailers are acceptable, and HTTP/1.1 clients
	// say it too (RFC 9110 §10.1.4). Gating the re-statement on the client's
	// protocol version instead of on what it actually asked for deleted the
	// request on every HTTP/1.1 connection, and the origin sent no trailers.
	if isRequest && hasOnlyTrailersToken(h.Values("Te")) {
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
