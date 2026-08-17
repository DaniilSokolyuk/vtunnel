package vtunnel_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/vivid-money/vtunnel"
)

// A WebSocket handshake is an ordinary HTTP request that the proxy must forward
// intact and then get out of the way of. Both halves used to be missing:
// removeHopByHop stripped Connection and Upgrade, which turns the handshake into
// a plain GET the upstream answers 200 to, and the forwarding path went through
// http.Transport, which has no way to return a 101 and the connection under it.
//
// The route shape decides who performs the upgrade, so each is covered here:
//
//   - ForwardTo — the proxy splices the client to the target
//   - Handle    — the caller's own handler upgrades, using the ResponseWriter it
//     was given, so the proxy only has to leave the headers alone
//   - Forward   — a byte pipe from the start; nothing to do, but it must not
//     have regressed
//
// The assertions deliberately go past "a message arrived": splicing rather than
// re-terminating is what keeps subprotocols, permessage-deflate and fragment
// boundaries as the endpoints negotiated them, and that is what a WebSocket
// library re-terminating in the middle — go-mitmproxy's approach — quietly loses.

func TestWebSocketThroughForwardTo(t *testing.T) {
	backend := wsEchoBackend(t, nil)

	proxy, proxyAddr := startSSEProxy(t, true, nil)
	proxy.ForwardTo("ws.test:443", backend.addr)

	conn := dialWS(t, proxyAddr, "wss://ws.test/socket", nil)
	defer conn.Close()

	assertEchoes(t, conn, "hello through the proxy")
}

// The point of terminating an upgrade rather than piping it: headers configured
// for the route have to land in the handshake, which is the only request a
// WebSocket connection ever makes.
func TestWebSocketHandshakeCarriesInjectedHeaders(t *testing.T) {
	seen := make(chan http.Header, 1)
	backend := wsEchoBackend(t, seen)

	proxy, proxyAddr := startSSEProxy(t, true, nil)
	proxy.ForwardTo("ws.test:443", backend.addr,
		vtunnel.WithHeader("Authorization", "Bearer ws-secret"),
		vtunnel.WithHeader("X-Env", "preview"))

	conn := dialWS(t, proxyAddr, "wss://ws.test/socket", nil)
	defer conn.Close()

	assertEchoes(t, conn, "authenticated")

	select {
	case h := <-seen:
		if got := h.Get("Authorization"); got != "Bearer ws-secret" {
			t.Fatalf("Authorization = %q, want the injected credential", got)
		}
		if got := h.Get("X-Env"); got != "preview" {
			t.Fatalf("X-Env = %q", got)
		}
		// The handshake itself must have survived the header surgery.
		if got := h.Get("Upgrade"); !strings.EqualFold(got, "websocket") {
			t.Fatalf("Upgrade = %q; the upstream did not receive a handshake", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never reported the handshake headers")
	}
}

// Splicing means the negotiation is between the endpoints, not with the proxy.
// A library re-terminating in the middle drops both of these.
func TestWebSocketSubprotocolAndCompressionSurvive(t *testing.T) {
	backend := wsEchoBackendWith(t, nil, &websocket.Upgrader{
		Subprotocols:      []string{"v2.echo"},
		EnableCompression: true,
		CheckOrigin:       func(*http.Request) bool { return true },
	})

	proxy, proxyAddr := startSSEProxy(t, true, nil)
	proxy.ForwardTo("ws.test:443", backend.addr)

	dialer := wsDialer(t, proxyAddr)
	dialer.Subprotocols = []string{"v2.echo", "v1.echo"}
	dialer.EnableCompression = true

	conn, resp, err := dialer.Dial("wss://ws.test/socket", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	defer resp.Body.Close()

	if got := conn.Subprotocol(); got != "v2.echo" {
		t.Fatalf("subprotocol = %q, want v2.echo — the proxy did not pass the negotiation through", got)
	}
	if got := resp.Header.Get("Sec-WebSocket-Extensions"); !strings.Contains(got, "permessage-deflate") {
		t.Fatalf("Sec-WebSocket-Extensions = %q, want permessage-deflate — compression was negotiated away", got)
	}

	assertEchoes(t, conn, strings.Repeat("compressible payload ", 50))
}

// A handler route holds the ResponseWriter, so it upgrades the connection
// itself. All the proxy owes it is an unmangled set of headers and a writer that
// can still be hijacked.
func TestWebSocketThroughHandlerRoute(t *testing.T) {
	upgrader := &websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

	proxy, proxyAddr := startSSEProxy(t, true, nil)
	proxy.Handle("ws.test:443", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		echoLoop(conn)
	}))

	conn := dialWS(t, proxyAddr, "wss://ws.test/socket", nil)
	defer conn.Close()

	assertEchoes(t, conn, "served in process")
}

// Middleware sits between the proxy and the upgrade, so a wrapper that hides
// Hijacker breaks it. This documents the contract stated on Use.
func TestWebSocketSurvivesMiddleware(t *testing.T) {
	backend := wsEchoBackend(t, nil)

	saw := make(chan string, 1)
	proxy, proxyAddr := startSSEProxy(t, true, func(p *vtunnel.MITMProxy) {
		p.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case saw <- r.URL.Path:
				default:
				}
				next.ServeHTTP(w, r)
			})
		})
	})
	proxy.ForwardTo("ws.test:443", backend.addr)

	conn := dialWS(t, proxyAddr, "wss://ws.test/socket", nil)
	defer conn.Close()
	assertEchoes(t, conn, "through middleware")

	select {
	case path := <-saw:
		if path != "/socket" {
			t.Fatalf("middleware saw path %q", path)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("middleware never saw the handshake")
	}
}

// A Forward route was already a byte pipe and needed no work — which is exactly
// why it is worth a regression test.
func TestWebSocketThroughUninterceptedPipe(t *testing.T) {
	backend := wsTLSEchoBackend(t)

	proxy, proxyAddr := startSSEProxy(t, false, nil) // no CA: nothing is decrypted
	proxy.ForwardTo("ws.test:443", backend.addr)

	conn := dialWS(t, proxyAddr, "wss://ws.test/socket", nil)
	defer conn.Close()

	assertEchoes(t, conn, "piped untouched")
}

// An upstream that declines the upgrade is answering an ordinary request, and
// the client has to receive that answer instead of a half-open connection.
func TestWebSocketUpstreamRefusalIsForwarded(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no sockets here", http.StatusForbidden)
	}))
	t.Cleanup(backend.Close)

	proxy, proxyAddr := startSSEProxy(t, true, nil)
	proxy.ForwardTo("ws.test:443", backend.Listener.Addr().String())

	_, resp, err := wsDialer(t, proxyAddr).Dial("wss://ws.test/socket", nil)
	if err == nil {
		t.Fatal("dial succeeded against an upstream that refuses upgrades")
	}
	if resp == nil {
		t.Fatalf("no response reached the client, only an error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want the upstream's 403", resp.StatusCode)
	}
}

// Cleartext ws:// never becomes a CONNECT, so it takes the plain-HTTP path on
// both sides. In the sandbox that path goes through http.Transport, which cannot
// carry an upgrade at all.
func TestWebSocketCleartextThroughEgress(t *testing.T) {
	backend := wsEchoBackend(t, nil)

	ts, server := startTunnelServer(t)
	defer ts.Close()

	egressPort := freePort(t)
	if err := server.StartProxy(fmt.Sprintf("127.0.0.1:%d", egressPort)); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	ca := generateTestCA(t)
	client := vtunnel.NewClient(wsURL(ts), vtunnel.WithMitm(ca))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	client.Proxy().ForwardTo("ws.test:80", backend.addr)

	// Deliberately not the gorilla Dialer's Proxy option: that issues a CONNECT
	// even for ws://, which would exercise the tunnel path and leave the egress proxy's
	// plain-HTTP path — the one that cannot carry an upgrade through
	// http.Transport — completely untested. This speaks to the egress proxy the way a
	// client honouring HTTP_PROXY for a ws:// URL does.
	conn := dialWSViaPlainProxy(t, fmt.Sprintf("127.0.0.1:%d", egressPort), "ws://ws.test/socket")
	defer conn.Close()

	assertEchoes(t, conn, "cleartext through the tunnel")
}

// A tls:// target puts a second TLS handshake in the path, and the upstream
// connection for it is pre-established during the client's handshake so its ALPN
// can be mirrored back. An upgrade cannot be expressed over h2, so what that
// negotiation settles on decides whether the connection is usable at all.
func TestWebSocketOverTLSUpstream(t *testing.T) {
	backend := httptest.NewUnstartedServer(wsEchoHandler(nil,
		&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}))
	// Offered even though an upgrade can never use it, so the negotiation is a
	// real choice rather than a foregone conclusion.
	backend.EnableHTTP2 = true
	backend.StartTLS()
	t.Cleanup(backend.Close)

	roots := x509.NewCertPool()
	roots.AddCert(backend.Certificate())

	proxy, proxyAddr := startSSEProxy(t, true, func(p *vtunnel.MITMProxy) {
		p.SetTransportTLSConfig(&tls.Config{RootCAs: roots})
	})
	proxy.ForwardTo("ws.test:443", "tls://"+backend.Listener.Addr().String())

	conn := dialWS(t, proxyAddr, "wss://ws.test/socket", nil)
	defer conn.Close()

	assertEchoes(t, conn, "through two TLS legs")
}

// The proxy mirrors the upstream's ALPN back to the client. A WebSocket client
// offers no ALPN at all, and the floor the proxy adds must therefore be
// HTTP/1.1: settling on h2 would leave the client speaking a handshake the
// connection cannot carry.
func TestWebSocketNegotiatesHTTP11(t *testing.T) {
	backend := httptest.NewUnstartedServer(wsEchoHandler(nil,
		&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}))
	backend.EnableHTTP2 = true
	backend.StartTLS()
	t.Cleanup(backend.Close)

	roots := x509.NewCertPool()
	roots.AddCert(backend.Certificate())

	proxy, proxyAddr := startSSEProxy(t, true, func(p *vtunnel.MITMProxy) {
		p.SetTransportTLSConfig(&tls.Config{RootCAs: roots})
	})
	proxy.ForwardTo("ws.test:443", "tls://"+backend.Listener.Addr().String())

	conn := dialWS(t, proxyAddr, "wss://ws.test/socket", nil)
	defer conn.Close()

	tlsConn, ok := conn.UnderlyingConn().(*tls.Conn)
	if !ok {
		t.Fatalf("underlying connection is %T, want a TLS connection", conn.UnderlyingConn())
	}
	if proto := tlsConn.ConnectionState().NegotiatedProtocol; proto == "h2" {
		t.Fatalf("the proxy offered h2 to a WebSocket client; an upgrade cannot be carried over it")
	}

	assertEchoes(t, conn, "negotiated for an upgrade")
}

// A spliced WebSocket has no request boundary and no context to cancel: it is
// two sockets copying into each other. Shutdown therefore cannot drain it and
// must end it at the deadline, closing both halves — otherwise the upstream is
// left holding a connection to a proxy that no longer exists.
func TestMITMProxyShutdownEndsLiveWebSocket(t *testing.T) {
	backendGone := make(chan struct{})
	backend := wsEchoBackendClosing(t, backendGone)

	proxy, proxyAddr := startSSEProxy(t, true, nil)
	proxy.ForwardTo("ws.test:443", backend.addr)

	conn := dialWS(t, proxyAddr, "wss://ws.test/socket", nil)
	defer conn.Close()
	assertEchoes(t, conn, "alive before shutdown")

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := proxy.Shutdown(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown err = %v, want context.DeadlineExceeded — a WebSocket never drains", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Shutdown blocked for %v on a socket that never ends", elapsed)
	}

	select {
	case <-backendGone:
	case <-time.After(10 * time.Second):
		t.Fatal("the upstream socket outlived the shutdown; the proxy closed only the client half")
	}

	// And the client has to find out too, rather than waiting on a dead peer.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("the client's socket still reads after Shutdown")
	}
}

// The same for the immediate stop, plus the leak check: a spliced socket owns
// two connections and two copy goroutines, so getting this wrong leaks both.
func TestMITMProxyCloseEndsLiveWebSocket(t *testing.T) {
	backendGone := make(chan struct{})
	backend := wsEchoBackendClosing(t, backendGone)

	settle(t)
	before := runtime.NumGoroutine()

	proxy, proxyAddr := startSSEProxy(t, true, nil)
	proxy.ForwardTo("ws.test:443", backend.addr)

	conn := dialWS(t, proxyAddr, "wss://ws.test/socket", nil)
	defer conn.Close()
	assertEchoes(t, conn, "alive before close")

	proxy.Close()

	select {
	case <-backendGone:
	case <-time.After(10 * time.Second):
		t.Fatal("the upstream socket outlived Close")
	}

	deadline := time.Now().Add(5 * time.Second)
	var after int
	for time.Now().Before(deadline) {
		runtime.GC()
		after = runtime.NumGoroutine()
		if after <= before+2 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("goroutines %d -> %d after Close; the spliced socket left work running", before, after)
}

// The cleartext path is where connection tracking earns its keep. A wss upgrade
// rides inside a CONNECT, and closing that one connection collapses everything
// above it — but a ws:// upgrade is hijacked straight off the outer server, and
// net/http stops tracking a connection the moment it is hijacked. Nothing but
// the proxy's own registry can reach it after that.
func TestMITMProxyCloseEndsLiveCleartextWebSocket(t *testing.T) {
	backendGone := make(chan struct{})
	backend := wsEchoBackendClosing(t, backendGone)

	settle(t)
	before := runtime.NumGoroutine()

	proxy, proxyAddr := startSSEProxy(t, true, nil)
	proxy.ForwardTo("ws.test:80", backend.addr)

	conn := dialWSViaPlainProxy(t, proxyAddr, "ws://ws.test/socket")
	defer conn.Close()
	assertEchoes(t, conn, "cleartext and alive")

	proxy.Close()

	select {
	case <-backendGone:
	case <-time.After(10 * time.Second):
		t.Fatal("the upstream socket outlived Close: the hijacked connection was never registered, " +
			"so nothing could reach it once net/http let go of it")
	}

	deadline := time.Now().Add(5 * time.Second)
	var after int
	for time.Now().Before(deadline) {
		runtime.GC()
		after = runtime.NumGoroutine()
		if after <= before+2 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("goroutines %d -> %d after Close", before, after)
}

// --- helpers ---

type wsBackend struct{ addr string }

// wsEchoBackendClosing reports when its end of the socket dies, which is how a
// test observes that a teardown reached past the proxy.
func wsEchoBackendClosing(t *testing.T, gone chan<- struct{}) *wsBackend {
	t.Helper()

	upgrader := &websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		echoLoop(conn)
		once.Do(func() { close(gone) })
	}))
	t.Cleanup(srv.Close)
	return &wsBackend{addr: srv.Listener.Addr().String()}
}

func wsEchoBackend(t *testing.T, seen chan<- http.Header) *wsBackend {
	t.Helper()
	return wsEchoBackendWith(t, seen, &websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }})
}

func wsEchoBackendWith(t *testing.T, seen chan<- http.Header, upgrader *websocket.Upgrader) *wsBackend {
	t.Helper()
	srv := httptest.NewServer(wsEchoHandler(seen, upgrader))
	t.Cleanup(srv.Close)
	return &wsBackend{addr: srv.Listener.Addr().String()}
}

func wsTLSEchoBackend(t *testing.T) *wsBackend {
	t.Helper()
	srv := httptest.NewUnstartedServer(wsEchoHandler(nil,
		&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &wsBackend{addr: srv.Listener.Addr().String()}
}

func wsEchoHandler(seen chan<- http.Header, upgrader *websocket.Upgrader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			h := http.Header{}
			for k, vs := range r.Header {
				h[k] = append([]string(nil), vs...)
			}
			select {
			case seen <- h:
			default:
			}
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		echoLoop(conn)
	}
}

func echoLoop(conn *websocket.Conn) {
	for {
		msgType, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if err := conn.WriteMessage(msgType, msg); err != nil {
			return
		}
	}
}

func wsDialer(t *testing.T, proxyAddr string) *websocket.Dialer {
	t.Helper()
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	return &websocket.Dialer{
		Proxy:            http.ProxyURL(proxyURL),
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		HandshakeTimeout: 10 * time.Second,
	}
}

func dialWS(t *testing.T, proxyAddr, rawURL string, header http.Header) *websocket.Conn {
	t.Helper()
	conn, resp, err := wsDialer(t, proxyAddr).Dial(rawURL, header)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
			t.Fatalf("dial %s: %v (status %d)", rawURL, err, resp.StatusCode)
		}
		t.Fatalf("dial %s: %v", rawURL, err)
	}
	resp.Body.Close()
	return conn
}

// dialWSViaPlainProxy opens a WebSocket by handing the handshake straight to a
// proxy as an ordinary HTTP request, with no CONNECT in front of it. Retries,
// because the route has to cross the tunnel before the sandbox knows it.
func dialWSViaPlainProxy(t *testing.T, proxyAddr, rawURL string) *websocket.Conn {
	t.Helper()

	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %s: %v", rawURL, err)
	}

	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		netConn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			lastErr = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		// NewClient performs the handshake over a connection that is already
		// open, which is exactly the shape needed here: the proxy is the peer,
		// and the Host header is what routes the request.
		conn, resp, err := websocket.NewClient(netConn, u, nil, 1024, 1024)
		if err == nil {
			resp.Body.Close()
			return conn
		}
		if resp != nil {
			resp.Body.Close()
		}
		netConn.Close()
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("handshake with %s through %s never succeeded: %v", rawURL, proxyAddr, lastErr)
	return nil
}

func assertEchoes(t *testing.T, conn *websocket.Conn, message string) {
	t.Helper()

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, got, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != message {
		t.Fatalf("echo = %q, want %q", got, message)
	}

	// A second exchange, because a proxy that mishandles the splice can still
	// get the first message through on whatever was already buffered.
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := conn.WriteMessage(websocket.TextMessage, []byte(message+" again")); err != nil {
		t.Fatalf("second write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, got, err = conn.ReadMessage()
	if err != nil {
		t.Fatalf("second read: %v", err)
	}
	if string(got) != message+" again" {
		t.Fatalf("second echo = %q", got)
	}
}

// Frame-level access needs no new API and no change to ForwardTo: Use wraps the
// upgrade too, so middleware that substitutes a ResponseWriter whose Hijack
// returns a wrapped connection sees every byte of the spliced socket. One
// connection carries both directions — reads are what the client sent, writes
// are what it received — so a single tap observes the whole conversation.
//
// This is the cheap end of inspection: the bytes are raw frames, so a tap can
// count them, log opcodes and sizes, or parse them, all without the proxy
// terminating the WebSocket and changing what the endpoints negotiated.
func TestWebSocketFramesCanBeTappedViaMiddleware(t *testing.T) {
	backend := wsEchoBackend(t, nil)

	var mu sync.Mutex
	var fromClient, toClient []byte

	proxy, proxyAddr := startSSEProxy(t, true, func(p *vtunnel.MITMProxy) {
		p.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// The very wrapper ExampleMITMProxy_Use_webSocketTap documents,
				// so the recipe shown in the docs is the one under test.
				next.ServeHTTP(&wsTapWriter{
					ResponseWriter: w,
					onRead:         func(b []byte) { mu.Lock(); fromClient = append(fromClient, b...); mu.Unlock() },
					onWrite:        func(b []byte) { mu.Lock(); toClient = append(toClient, b...); mu.Unlock() },
				}, r)
			})
		})
	})
	proxy.ForwardTo("ws.test:443", backend.addr)

	conn := dialWS(t, proxyAddr, "wss://ws.test/socket", nil)
	defer conn.Close()
	assertEchoes(t, conn, "tapped payload")
	conn.Close()

	mu.Lock()
	defer mu.Unlock()

	if len(fromClient) == 0 {
		t.Fatal("the tap saw nothing from the client")
	}
	// Client frames are masked, so only the server's direction is plaintext.
	if !strings.Contains(string(toClient), "tapped payload") {
		t.Fatalf("the tap did not see the echoed payload; got %d bytes back from the upstream", len(toClient))
	}
	// Opcode 0x81 is FIN plus a text frame: what the tap holds really is frames,
	// not some re-encoded stand-in.
	if !strings.Contains(string(toClient), "\x81") {
		t.Fatal("the tapped bytes contain no text-frame header")
	}
}

// Cleartext in, TLS out: the sandbox application speaks ws:// to the proxy and
// the proxy re-encrypts to a wss:// upstream. This is the one upgrade path with
// no pre-established upstream connection to reuse — the plain-HTTP path never
// had a client handshake to mirror one onto — so dialUpstreamConn has to build
// the TLS leg itself, offering only HTTP/1.1 because an upgrade cannot be
// carried over h2.
func TestWebSocketCleartextClientToTLSUpstream(t *testing.T) {
	upstream := httptest.NewUnstartedServer(wsEchoHandler(nil,
		&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}))
	upstream.EnableHTTP2 = true // offered, and must not be chosen for an upgrade
	upstream.StartTLS()
	t.Cleanup(upstream.Close)

	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())

	proxy, proxyAddr := startSSEProxy(t, true, func(p *vtunnel.MITMProxy) {
		p.SetTransportTLSConfig(&tls.Config{RootCAs: roots})
	})
	proxy.ForwardTo("ws.test:80", "tls://"+upstream.Listener.Addr().String())

	conn := dialWSViaPlainProxy(t, proxyAddr, "ws://ws.test/socket")
	defer conn.Close()

	assertEchoes(t, conn, "cleartext in, TLS out")
}
