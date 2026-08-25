package e2e_test

// The interception matrix: every way an application can reach the proxy,
// crossed with every way the proxy can reach the upstream, for each of the
// three response shapes that break differently — a whole body, a stream, and a
// long-lived socket.
//
// Each leg negotiates its protocol and its encryption on its own. An h2 client
// against an HTTP/1.1 upstream is a different code path from an h2 client
// against an h2 upstream, which is different again from the same pair reached
// over cleartext h2c, and each of those has its own copy loop. Point tests cover
// the cells someone thought to write down; this covers the product.
//
// What every cell asserts is the same three things:
//
//   - the payload survived, byte for byte;
//   - the controlplane's injected header reached the upstream, which is what
//     distinguishes interception from a byte pipe that merely worked;
//   - both legs spoke the protocol they were supposed to, which is what
//     distinguishes interception from a fallback that quietly gave up.

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/vivid-money/vtunnel"
)

const (
	matrixHost     = "matrix.test"
	injectedHeader = "X-Vtunnel-Injected"
	injectedValue  = "controlplane"
)

// ---------------------------------------------------------------------------
// Upstreams: the four shapes a route target can take.
// ---------------------------------------------------------------------------

type upstream struct {
	name   string
	kind   upstreamKind
	target string         // what ForwardTo is pointed at
	roots  *x509.CertPool // the upstream's own CA, nil when it speaks cleartext
}

type upstreamKind int

const (
	upClearH1 upstreamKind = iota // cleartext HTTP/1.1
	upTLSH1                       // TLS, http/1.1 only in its ALPN
	upTLSH2                       // TLS, offering h2 and http/1.1
	upH2C                         // cleartext HTTP/2 by prior knowledge
)

var upstreamModes = []struct {
	name  string
	kind  upstreamKind
	start func(t *testing.T, h http.Handler) (target string, roots *x509.CertPool)
}{
	{"upstream=h1", upClearH1, startH1Upstream},
	{"upstream=tls-h1", upTLSH1, startTLSH1Upstream},
	{"upstream=tls-h2", upTLSH2, startTLSH2Upstream},
	{"upstream=h2c", upH2C, startH2CUpstream},
}

func startH1Upstream(t *testing.T, h http.Handler) (string, *x509.CertPool) {
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts.Listener.Addr().String(), nil
}

func startTLSH1Upstream(t *testing.T, h http.Handler) (string, *x509.CertPool) {
	ts := httptest.NewUnstartedServer(h)
	ts.StartTLS()
	t.Cleanup(ts.Close)

	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	return "tls://" + ts.Listener.Addr().String(), roots
}

func startTLSH2Upstream(t *testing.T, h http.Handler) (string, *x509.CertPool) {
	ts := httptest.NewUnstartedServer(h)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)

	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	return "tls://" + ts.Listener.Addr().String(), roots
}

// startH2CUpstream serves HTTP/2 in the clear — no TLS, so no ALPN to negotiate
// it: the server accepts the preface by prior knowledge, which is what the
// h2c:// scheme on a route tells the proxy to send.
func startH2CUpstream(t *testing.T, h http.Handler) (string, *x509.CertPool) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: h2c.NewHandler(h, &http2.Server{})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "h2c://" + ln.Addr().String(), nil
}

// newUpstreamChain starts one upstream and the whole tunnel in front of it,
// with matrixHost routed to it and a header injected on the way.
func newUpstreamChain(t *testing.T, mode int, h http.Handler) (*chain, upstream) {
	t.Helper()

	m := upstreamModes[mode]
	target, roots := m.start(t, h)
	up := upstream{name: m.name, kind: m.kind, target: target, roots: roots}

	c := newChain(t, func(p *vtunnel.MITMProxy) {
		if roots != nil {
			p.SetTransportTLSConfig(&tls.Config{RootCAs: roots})
		}
	})
	if err := c.proxy.ForwardTo(matrixHost, target, vtunnel.WithHeader(injectedHeader, injectedValue)); err != nil {
		t.Fatalf("ForwardTo(%s): %v", target, err)
	}
	c.waitRoute(t, matrixHost)
	return c, up
}

// ---------------------------------------------------------------------------
// Clients: the four ways an application reaches the egress proxy.
// ---------------------------------------------------------------------------

type clientMode struct {
	name   string
	scheme string // what the application puts in front of matrixHost
	h2     bool   // whether it asks for HTTP/2
	tls    bool   // whether it asks over TLS, and so has an ALPN to be answered
	build  func(t *testing.T, c *chain) *http.Client
}

var clientModes = []clientMode{
	{"client=h1-clear", "http", false, false, buildH1Clear},
	{"client=h1-tls", "https", false, true, buildH1TLS},
	{"client=h2-tls", "https", true, true, buildH2TLS},
	{"client=h2c-clear", "http", true, false, buildH2CClear},
}

// negotiated is the protocol each leg must end up speaking, and it is not a
// free choice on either side:
//
//   - The upstream decides its own leg. The proxy offers it both protocols
//     whatever the client is doing, so that no pairing is unreachable, and the
//     upstream picks — from its own list, since the server is what chooses in
//     ALPN. An h2-capable upstream therefore gets h2 even from an HTTP/1.1
//     client, and the proxy translates.
//   - What the upstream settled on is then mirrored into the ALPN answered to a
//     TLS client, so the two legs agree whenever they can and nothing is
//     translated for no reason. A client that did not offer that protocol is
//     answered with what it did offer instead, and translated after all.
//   - A cleartext client has no handshake to be answered in, so it keeps
//     whatever it started speaking.
//   - h2c:// states the upstream protocol outright rather than negotiating it.
func negotiated(up upstreamKind, cl clientMode) (clientProto, upstreamProto string) {
	upH2 := up == upH2C || up == upTLSH2

	clH2 := cl.h2
	if cl.tls && (up == upTLSH1 || up == upTLSH2) {
		clH2 = upH2 && cl.h2 // mirrored, then narrowed to what the client can take
	}
	return proto(clH2), proto(upH2)
}

func proto(h2 bool) string {
	if h2 {
		return "HTTP/2.0"
	}
	return "HTTP/1.1"
}

func buildH1Clear(t *testing.T, c *chain) *http.Client {
	return matrixClient(t, &http.Transport{Proxy: c.proxyURL()})
}

// buildH1TLS offers only http/1.1 in the ALPN of the tunnelled handshake, so
// the proxy's leaf is negotiated down even when the upstream speaks h2.
func buildH1TLS(t *testing.T, c *chain) *http.Client {
	return matrixClient(t, &http.Transport{
		Proxy: c.proxyURL(),
		TLSClientConfig: &tls.Config{
			RootCAs:    c.caPool,
			NextProtos: []string{"http/1.1"},
		},
	})
}

func buildH2TLS(t *testing.T, c *chain) *http.Client {
	return matrixClient(t, &http.Transport{
		Proxy:             c.proxyURL(),
		TLSClientConfig:   &tls.Config{RootCAs: c.caPool},
		ForceAttemptHTTP2: true,
	})
}

// buildH2CClear speaks HTTP/2 in the clear inside a CONNECT tunnel: no TLS, no
// ALPN, just the preface. It is how a gRPC client reaches a plaintext service
// through a proxy, and the only client path where interception happens without
// a certificate being issued at all.
func buildH2CClear(t *testing.T, c *chain) *http.Client {
	return matrixClient(t, &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, _, addr string, _ *tls.Config) (net.Conn, error) {
			return connectThroughProxy(ctx, c.proxyAddr, addr)
		},
	})
}

func matrixClient(t *testing.T, rt http.RoundTripper) *http.Client {
	t.Cleanup(func() {
		if c, ok := rt.(interface{ CloseIdleConnections() }); ok {
			c.CloseIdleConnections()
		}
	})
	return &http.Client{Transport: rt, Timeout: 20 * time.Second}
}

func (c *chain) proxyURL() func(*http.Request) (*url.URL, error) {
	return http.ProxyURL(&url.URL{Scheme: "http", Host: c.proxyAddr})
}

// ---------------------------------------------------------------------------
// A whole body, in every cell, compressed and not.
// ---------------------------------------------------------------------------

const matrixPayload = "the quick brown fox jumps over the lazy dog, repeatedly and at length, " +
	"so that gzip has something to actually compress and a short read cannot pass for a whole one"

// echoUpstream answers with a description of the request that reached it, so a
// client can tell from the body alone which protocol the far leg spoke and
// whether the controlplane's header injection survived the crossing. It
// compresses when asked, the way any real server does.
func echoUpstream() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := fmt.Sprintf("proto=%s injected=%s ae=%s payload=%s",
			r.Proto, r.Header.Get(injectedHeader), r.Header.Get("Accept-Encoding"), matrixPayload)

		w.Header().Set("Content-Type", "text/plain")
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			io.WriteString(w, body)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		io.WriteString(zw, body)
		zw.Close()
	})
}

func TestMatrixWholeBody(t *testing.T) {
	for mode := range upstreamModes {
		t.Run(upstreamModes[mode].name, func(t *testing.T) {
			c, up := newUpstreamChain(t, mode, echoUpstream())

			for _, cl := range clientModes {
				for _, askGzip := range []bool{false, true} {
					name := cl.name + "/gzip=transparent"
					if askGzip {
						name = cl.name + "/gzip=passthrough"
					}
					t.Run(name, func(t *testing.T) {
						client := cl.build(t, c)

						req, err := http.NewRequest(http.MethodGet, cl.scheme+"://"+matrixHost+"/echo", nil)
						if err != nil {
							t.Fatalf("new request: %v", err)
						}
						// Setting it by hand is what turns off net/http's own
						// transparent gzip, leaving the encoded bytes for us.
						if askGzip {
							req.Header.Set("Accept-Encoding", "gzip")
						}

						resp, err := client.Do(req)
						if err != nil {
							t.Fatalf("GET: %v", err)
						}
						defer resp.Body.Close()

						wantClient, wantUpstream := negotiated(up.kind, cl)
						if resp.Proto != wantClient {
							t.Errorf("client leg spoke %s, want %s", resp.Proto, wantClient)
						}

						enc := resp.Header.Get("Content-Encoding")
						var body []byte
						if askGzip {
							if enc != "gzip" {
								t.Fatalf("Content-Encoding = %q, want gzip: the client asked for the "+
									"compressed bytes and must get them untouched", enc)
							}
							zr, err := gzip.NewReader(resp.Body)
							if err != nil {
								t.Fatalf("gzip reader: %v", err)
							}
							body, err = io.ReadAll(zr)
							if err != nil {
								t.Fatalf("read gzip body: %v", err)
							}
						} else {
							if enc != "" {
								t.Fatalf("Content-Encoding = %q on a client that never asked for it: "+
									"the header and the body no longer agree", enc)
							}
							body, err = io.ReadAll(resp.Body)
							if err != nil {
								t.Fatalf("read body: %v", err)
							}
						}

						assertUpstreamSaw(t, string(body), wantUpstream)
						if !strings.HasSuffix(string(body), matrixPayload) {
							t.Errorf("payload did not survive: body = %.120q...", body)
						}
					})
				}
			}
		})
	}
}

// assertUpstreamSaw checks the two things the upstream is in a position to tell
// us and the client is not: which protocol reached it, and whether the
// controlplane rewrote the request on the way.
func assertUpstreamSaw(t *testing.T, body, wantProto string) {
	t.Helper()

	if !strings.Contains(body, "proto="+wantProto+" ") {
		t.Errorf("upstream leg spoke the wrong protocol: want proto=%s, got %.60q", wantProto, body)
	}
	if !strings.Contains(body, "injected="+injectedValue+" ") {
		t.Errorf("injected header never reached the upstream — the connection was piped, not intercepted: %.90q", body)
	}
	if !strings.Contains(body, "ae=gzip") {
		t.Errorf("upstream was not offered gzip: %.90q", body)
	}
}

// ---------------------------------------------------------------------------
// A stream, in every cell, compressed and not.
// ---------------------------------------------------------------------------

const (
	sseEvents = 5
	sseGap    = 60 * time.Millisecond
)

// sseUpstream emits events spread out in time. Compression is the interesting
// part: a gzip writer that is not flushed per event turns a stream into a
// batch, and the client cannot tell the difference until the very end.
func sseUpstream() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")

		gz := strings.Contains(r.Header.Get("Accept-Encoding"), "gzip")
		if gz {
			w.Header().Set("Content-Encoding", "gzip")
		}
		w.WriteHeader(http.StatusOK)

		var zw *gzip.Writer
		out := io.Writer(w)
		if gz {
			zw = gzip.NewWriter(w)
			out = zw
		}
		rc := http.NewResponseController(w)

		for i := range sseEvents {
			fmt.Fprintf(out, "data: event-%d proto=%s injected=%s\n\n",
				i, r.Proto, r.Header.Get(injectedHeader))
			if zw != nil {
				zw.Flush()
			}
			if err := rc.Flush(); err != nil {
				return
			}
			time.Sleep(sseGap)
		}
		if zw != nil {
			zw.Close()
		}
	})
}

func TestMatrixSSE(t *testing.T) {
	for mode := range upstreamModes {
		t.Run(upstreamModes[mode].name, func(t *testing.T) {
			c, up := newUpstreamChain(t, mode, sseUpstream())

			for _, cl := range clientModes {
				for _, askGzip := range []bool{false, true} {
					name := cl.name + "/gzip=transparent"
					if askGzip {
						name = cl.name + "/gzip=passthrough"
					}
					t.Run(name, func(t *testing.T) {
						client := cl.build(t, c)

						req, err := http.NewRequest(http.MethodGet, cl.scheme+"://"+matrixHost+"/events", nil)
						if err != nil {
							t.Fatalf("new request: %v", err)
						}
						if askGzip {
							req.Header.Set("Accept-Encoding", "gzip")
						}

						resp, err := client.Do(req)
						if err != nil {
							t.Fatalf("GET: %v", err)
						}
						defer resp.Body.Close()

						wantClient, wantUpstream := negotiated(up.kind, cl)
						if resp.Proto != wantClient {
							t.Errorf("client leg spoke %s, want %s", resp.Proto, wantClient)
						}

						body := io.Reader(resp.Body)
						if askGzip {
							if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
								t.Fatalf("Content-Encoding = %q, want gzip", got)
							}
							zr, err := gzip.NewReader(resp.Body)
							if err != nil {
								t.Fatalf("gzip reader: %v", err)
							}
							body = zr
						}

						events, arrivals := collectSSE(t, body, sseEvents)
						assertStreamed(t, arrivals)

						for i, ev := range events {
							if want := fmt.Sprintf("event-%d ", i); !strings.Contains(ev, want) {
								t.Fatalf("event %d = %q, want one containing %q", i, ev, want)
							}
						}
						if !strings.Contains(events[0], "proto="+wantUpstream+" ") {
							t.Errorf("upstream leg spoke the wrong protocol: want %s, got %q", wantUpstream, events[0])
						}
						if !strings.Contains(events[0], "injected="+injectedValue) {
							t.Errorf("injected header never reached the upstream: %q", events[0])
						}
					})
				}
			}
		})
	}
}

// collectSSE reads n events and records when each one arrived. The timings are
// the assertion; the payloads are only there to prove nothing was reordered.
func collectSSE(t *testing.T, r io.Reader, n int) (events []string, arrivals []time.Duration) {
	t.Helper()

	start := time.Now()
	buf := make([]byte, 512)
	var pending string
	for len(events) < n {
		nr, err := r.Read(buf)
		if nr > 0 {
			pending += string(buf[:nr])
			for {
				i := strings.Index(pending, "\n\n")
				if i < 0 {
					break
				}
				events = append(events, strings.TrimPrefix(pending[:i], "data: "))
				arrivals = append(arrivals, time.Since(start))
				pending = pending[i+2:]
			}
		}
		if err != nil {
			t.Fatalf("read event %d of %d: %v", len(events), n, err)
		}
	}
	return events, arrivals
}

// assertStreamed is the whole point of the SSE cells: a proxy that buffers
// delivers every event too, just all at once at the end.
func assertStreamed(t *testing.T, arrivals []time.Duration) {
	t.Helper()

	spread := arrivals[len(arrivals)-1] - arrivals[0]
	if min := time.Duration(len(arrivals)-1) * sseGap / 2; spread < min {
		t.Fatalf("events arrived %v apart, want at least %v — the stream was batched, not streamed (%v)",
			spread, min, arrivals)
	}
}

// ---------------------------------------------------------------------------
// A long-lived socket, both directions, over both encryptions.
// ---------------------------------------------------------------------------

// wsUpstream greets the client with what it saw of the handshake, echoes
// whatever it is sent, and pushes unsolicited messages on request — so a test
// can drive traffic in both directions on one connection.
func wsUpstream(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		greeting := fmt.Sprintf("hello proto=%s injected=%s", r.Proto, r.Header.Get(injectedHeader))
		if err := conn.WriteMessage(websocket.TextMessage, []byte(greeting)); err != nil {
			return
		}

		for {
			mt, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if string(msg) == "push" {
				for i := range 3 {
					if err := conn.WriteMessage(websocket.TextMessage, fmt.Appendf(nil, "push-%d", i)); err != nil {
						return
					}
				}
				continue
			}
			if err := conn.WriteMessage(mt, append([]byte("echo:"), msg...)); err != nil {
				return
			}
		}
	})
}

var wsUpstreamModes = []struct {
	name  string
	start func(t *testing.T, h http.Handler) (target string, roots *x509.CertPool)
}{
	{"upstream=ws", startH1Upstream},
	{"upstream=wss", startTLSH1Upstream},
}

func TestMatrixWebSocket(t *testing.T) {
	for _, um := range wsUpstreamModes {
		t.Run(um.name, func(t *testing.T) {
			target, roots := um.start(t, wsUpstream(t))

			c := newChain(t, func(p *vtunnel.MITMProxy) {
				if roots != nil {
					p.SetTransportTLSConfig(&tls.Config{RootCAs: roots})
				}
			})
			if err := c.proxy.ForwardTo(matrixHost, target, vtunnel.WithHeader(injectedHeader, injectedValue)); err != nil {
				t.Fatalf("ForwardTo: %v", err)
			}
			c.waitRoute(t, matrixHost)

			for _, scheme := range []string{"ws", "wss"} {
				for _, compress := range []bool{false, true} {
					name := "client=" + scheme + "/deflate=off"
					if compress {
						name = "client=" + scheme + "/deflate=on"
					}
					t.Run(name, func(t *testing.T) {
						conn := dialMatrixWS(t, c, scheme, compress)
						defer conn.Close()

						if got := conn.Subprotocol(); got != "vtunnel.matrix" {
							t.Errorf("subprotocol = %q, want vtunnel.matrix", got)
						}

						greeting := readWSText(t, conn)
						if !strings.Contains(greeting, "injected="+injectedValue) {
							t.Errorf("injected header never reached the upstream handshake: %q", greeting)
						}
						// RFC 6455 has no HTTP/2 form, so both legs must be
						// HTTP/1.1 no matter what the client offered in ALPN.
						if !strings.Contains(greeting, "proto=HTTP/1.1") {
							t.Errorf("upstream handshake was not HTTP/1.1: %q", greeting)
						}

						// Client to server and back, several times on the one
						// connection, so a proxy that survives the handshake but
						// wedges on the second frame is still caught.
						for _, msg := range []string{"alpha", "beta", "gamma"} {
							if err := conn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
								t.Fatalf("write %q: %v", msg, err)
							}
							if got, want := readWSText(t, conn), "echo:"+msg; got != want {
								t.Fatalf("echo = %q, want %q", got, want)
							}
						}

						// Binary frames take a different path through gorilla's
						// compression than text ones do.
						payload := []byte(matrixPayload)
						if err := conn.WriteMessage(websocket.BinaryMessage, payload); err != nil {
							t.Fatalf("write binary: %v", err)
						}
						mt, got, err := conn.ReadMessage()
						if err != nil {
							t.Fatalf("read binary echo: %v", err)
						}
						if mt != websocket.BinaryMessage {
							t.Errorf("echo message type = %d, want binary", mt)
						}
						if string(got) != "echo:"+string(payload) {
							t.Errorf("binary echo did not survive: %.60q", got)
						}

						// Server to client, unsolicited: the direction a
						// half-duplex proxy gets wrong.
						if err := conn.WriteMessage(websocket.TextMessage, []byte("push")); err != nil {
							t.Fatalf("write push: %v", err)
						}
						for i := range 3 {
							if got, want := readWSText(t, conn), fmt.Sprintf("push-%d", i); got != want {
								t.Fatalf("push %d = %q, want %q", i, got, want)
							}
						}
					})
				}
			}
		})
	}
}

func dialMatrixWS(t *testing.T, c *chain, scheme string, compress bool) *websocket.Conn {
	t.Helper()

	d := &websocket.Dialer{
		Proxy:             c.proxyURL(),
		TLSClientConfig:   &tls.Config{RootCAs: c.caPool},
		Subprotocols:      []string{"vtunnel.matrix"},
		EnableCompression: compress,
		HandshakeTimeout:  20 * time.Second,
	}
	conn, resp, err := d.Dial(scheme+"://"+matrixHost+"/ws", nil)
	if err != nil {
		status := ""
		if resp != nil {
			status = " (" + resp.Status + ")"
		}
		t.Fatalf("dial %s://%s%s: %v", scheme, matrixHost, status, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func readWSText(t *testing.T, conn *websocket.Conn) string {
	t.Helper()

	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	mt, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read message: %v", err)
	}
	if mt != websocket.TextMessage {
		t.Fatalf("message type = %d, want text", mt)
	}
	return string(msg)
}
