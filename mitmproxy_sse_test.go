package vtunnel_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

// SSE is the traffic vtunnel exists to carry: LLM streaming APIs answer with
// text/event-stream, and an agent that receives the whole stream in one batch at
// the end behaves as if the response arrived empty. TestProxyHTTP_SSEStreamsEventByEvent
// pins this down for one path only — plain HTTP through a tunnel. Every other way
// a route can be served has its own copy loop, and each can buffer independently:
//
//   - ForwardTo + MITM, HTTP/1.1 client   -> serveH1 -> forwardingHandler -> copyResponse
//   - ForwardTo + MITM, HTTP/2 client     -> serveH2 -> same, over an h2 ResponseWriter
//   - ForwardTo + tls:// upstream, h2     -> upstreamRoundTripper -> http2.Transport
//   - Handle (in-process)                 -> the handler's own ResponseWriter
//   - no CA (raw byte pipe)               -> dualStream
//   - plain HTTP, no tunnel               -> handleHTTP
//
// These tests cover that matrix. The assertion that matters in all of them is not
// "every event arrived" — a buffering proxy delivers those too, just late — but
// that the events were spread out in time the way the upstream emitted them.

const (
	sseEventCount = 5
	sseGap        = 60 * time.Millisecond
)

// TestSSE_MITM_HTTP11 covers the main interception path: CONNECT, TLS terminated
// with a generated leaf, request re-issued to the target over HTTP/1.1.
func TestSSE_MITM_HTTP11(t *testing.T) {
	backend := sseBackend(t, "h1")

	proxy, proxyAddr := startSSEProxy(t, true, nil)
	proxy.ForwardTo("sse.test:443", backend.Listener.Addr().String())

	resp := sseGet(t, sseProxyClient(t, proxyAddr, false), "https://sse.test/v1/messages")
	defer resp.Body.Close()

	if resp.ProtoMajor != 1 {
		t.Fatalf("client protocol = HTTP/%d, want HTTP/1.x", resp.ProtoMajor)
	}
	assertStreamed(t, collectSSE(t, resp.Body, sseEventCount))
}

// TestSSE_MITM_HTTP2Client covers an h2 client against an HTTP/1.1 upstream —
// the ALPN translation path (mitmproxy.go serveMITMTLS). The response crosses a
// protocol boundary, so it is copied through an http2 ResponseWriter whose
// flushing is separate from the HTTP/1.1 one.
func TestSSE_MITM_HTTP2Client(t *testing.T) {
	backend := sseBackend(t, "h2client")

	proxy, proxyAddr := startSSEProxy(t, true, nil)
	proxy.ForwardTo("sse.test:443", backend.Listener.Addr().String())

	resp := sseGet(t, sseProxyClient(t, proxyAddr, true), "https://sse.test/v1/messages")
	defer resp.Body.Close()

	if resp.ProtoMajor != 2 {
		t.Fatalf("client protocol = HTTP/%d, want HTTP/2 — the h2 path was not exercised", resp.ProtoMajor)
	}
	assertStreamed(t, collectSSE(t, resp.Body, sseEventCount))
}

// TestSSE_TLSUpstreamHTTP2 covers h2 on both sides: the client negotiates h2 with
// the proxy, and the proxy negotiates h2 with a TLS upstream, so the body travels
// through http2.Transport rather than http.Transport.
func TestSSE_TLSUpstreamHTTP2(t *testing.T) {
	backend := httptest.NewUnstartedServer(sseHandler(t, "tlsh2"))
	backend.EnableHTTP2 = true
	backend.StartTLS()
	t.Cleanup(backend.Close)

	roots := x509.NewCertPool()
	roots.AddCert(backend.Certificate())

	proxy, proxyAddr := startSSEProxy(t, true, func(p *vtunnel.MITMProxy) {
		// Must be set before Start, hence the setup hook.
		p.SetTransportTLSConfig(&tls.Config{RootCAs: roots})
	})
	proxy.ForwardTo("sse.test:443", "tls://"+backend.Listener.Addr().String())

	resp := sseGet(t, sseProxyClient(t, proxyAddr, true), "https://sse.test/v1/messages")
	defer resp.Body.Close()

	if resp.ProtoMajor != 2 {
		t.Fatalf("client protocol = HTTP/%d, want HTTP/2", resp.ProtoMajor)
	}
	assertStreamed(t, collectSSE(t, resp.Body, sseEventCount))
}

// TestSSE_HandlerRoute covers a route served in this process. There is no upstream
// at all: the handler writes to the ResponseWriter the proxy handed it, so this
// pins down that the proxy does not wrap that writer in something unflushable.
func TestSSE_HandlerRoute(t *testing.T) {
	proxy, proxyAddr := startSSEProxy(t, true, nil)
	proxy.Handle("sse.test:443", sseHandler(t, "handler"))

	resp := sseGet(t, sseProxyClient(t, proxyAddr, false), "https://sse.test/v1/messages")
	defer resp.Body.Close()

	assertStreamed(t, collectSSE(t, resp.Body, sseEventCount))
}

// TestSSE_NoCA_RawPipe covers a proxy with no CA: the route still resolves, but
// TLS is piped through untouched by dualStream. Nothing parses the response, so
// this mostly guards against the pipe growing a buffer.
func TestSSE_NoCA_RawPipe(t *testing.T) {
	backend := httptest.NewUnstartedServer(sseHandler(t, "pipe"))
	backend.StartTLS()
	t.Cleanup(backend.Close)

	proxy, proxyAddr := startSSEProxy(t, false, nil)
	proxy.ForwardTo("sse.test:443", backend.Listener.Addr().String())

	resp := sseGet(t, sseProxyClient(t, proxyAddr, false), "https://sse.test/v1/messages")
	defer resp.Body.Close()

	assertStreamed(t, collectSSE(t, resp.Body, sseEventCount))
}

// TestSSE_PlainHTTP covers handleHTTP — a cleartext request that never becomes a
// CONNECT tunnel. This is the path the existing tunnel test exercises; here it
// runs without a tunnel so a failure points at the proxy rather than the transport.
func TestSSE_PlainHTTP(t *testing.T) {
	backend := sseBackend(t, "plain")

	proxy, proxyAddr := startSSEProxy(t, true, nil)
	proxy.ForwardTo("sse.test:80", backend.Listener.Addr().String())

	resp := sseGet(t, sseProxyClient(t, proxyAddr, false), "http://sse.test/v1/messages")
	defer resp.Body.Close()

	assertStreamed(t, collectSSE(t, resp.Body, sseEventCount))
}

// TestSSE_HeaderInjection is the combination that actually ships: a credential is
// injected into a stream. Injection rewrites request headers, which must not cost
// the response its incremental delivery.
func TestSSE_HeaderInjection(t *testing.T) {
	seen := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case seen <- r.Header.Get("Authorization"):
		default:
		}
		sseHandler(t, "inject")(w, r)
	}))
	t.Cleanup(backend.Close)

	proxy, proxyAddr := startSSEProxy(t, true, nil)
	proxy.ForwardTo("sse.test:443", backend.Listener.Addr().String(),
		vtunnel.WithHeader("Authorization", "Bearer streamed"))

	resp := sseGet(t, sseProxyClient(t, proxyAddr, false), "https://sse.test/v1/messages")
	defer resp.Body.Close()

	assertStreamed(t, collectSSE(t, resp.Body, sseEventCount))

	select {
	case got := <-seen:
		if got != "Bearer streamed" {
			t.Fatalf("upstream saw Authorization = %q, want the injected credential", got)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream never reported the request headers")
	}
}

// --- helpers ---

// sseHandler emits sseEventCount events, one every sseGap, flushing each. A proxy
// that streams correctly delivers them one at a time; one that buffers delivers
// them all once the handler returns.
func sseHandler(t *testing.T, prefix string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		rc := http.NewResponseController(w)
		for i := range sseEventCount {
			if _, err := fmt.Fprintf(w, "event: message\ndata: %s-%d\n\n", prefix, i); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
			select {
			case <-r.Context().Done():
				return
			case <-time.After(sseGap):
			}
		}
	}
}

func sseBackend(t *testing.T, prefix string) *httptest.Server {
	t.Helper()
	backend := httptest.NewServer(sseHandler(t, prefix))
	t.Cleanup(backend.Close)
	return backend
}

// startSSEProxy starts a MITMProxy, optionally with a CA, running setup before
// Start for options that only take effect beforehand.
func startSSEProxy(t *testing.T, withCA bool, setup func(*vtunnel.MITMProxy)) (*vtunnel.MITMProxy, string) {
	t.Helper()

	var proxy *vtunnel.MITMProxy
	if withCA {
		proxy = vtunnel.NewMITMProxy(vtunnel.WithMitmCA(generateTestCA(t)))
	} else {
		proxy = vtunnel.NewMITMProxy()
	}
	if setup != nil {
		setup(proxy)
	}
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("proxy Start: %v", err)
	}
	t.Cleanup(proxy.Close)
	return proxy, proxy.Addr().String()
}

// sseProxyClient builds a client that talks to the proxy, optionally offering h2
// in the ALPN of the tunnelled handshake. Keep-alives stay on: h2 needs them.
func sseProxyClient(t *testing.T, proxyAddr string, h2 bool) *http.Client {
	t.Helper()
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(mustParseURL(t, "http://"+proxyAddr)),
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: h2,
		},
	}
}

func sseGet(t *testing.T, c *http.Client, rawURL string) *http.Response {
	t.Helper()
	resp, err := c.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("GET %s: status %d", rawURL, resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		resp.Body.Close()
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}
	return resp
}

// collectSSE reads want data: lines, recording when each arrived relative to the
// first read. It fails rather than returning short, so callers can assume length.
func collectSSE(t *testing.T, body io.Reader, want int) []time.Duration {
	t.Helper()

	start := time.Now()
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	arrivals := make([]time.Duration, 0, want)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "data:") {
			arrivals = append(arrivals, time.Since(start))
			if len(arrivals) == want {
				break
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read stream: %v (got %d/%d events)", err, len(arrivals), want)
	}
	if len(arrivals) != want {
		t.Fatalf("got %d events, want %d", len(arrivals), want)
	}
	return arrivals
}

// assertStreamed fails when the events show up as one batch instead of trickling
// in. The primary check is the spread between first and last arrival: a buffering
// proxy delivers every event at once, so that spread collapses to ~0 regardless of
// how slow the machine is. The first-arrival bound is secondary and deliberately
// generous, since it is the only one sensitive to a loaded CI box.
func assertStreamed(t *testing.T, arrivals []time.Duration) {
	t.Helper()

	spread := arrivals[len(arrivals)-1] - arrivals[0]
	minSpread := time.Duration(len(arrivals)-1) * sseGap / 2
	if spread < minSpread {
		t.Fatalf("events arrived within %v of each other (want >%v spread) — the proxy is buffering the stream; arrivals: %v",
			spread, minSpread, arrivals)
	}

	if maxFirst := 4 * sseGap; arrivals[0] > maxFirst {
		t.Fatalf("first event arrived after %v (max %v) — the proxy delayed the head of the stream; arrivals: %v",
			arrivals[0], maxFirst, arrivals)
	}
}

// Rewriting an SSE stream needs no new API either: Use wraps every terminated
// request, and the proxy copies the upstream body into whatever ResponseWriter
// the middleware handed down. Intercepting Write is therefore enough to see and
// change events as they pass.
//
// The catch is Unwrap. Incremental delivery depends on flushingCopy calling
// http.ResponseController.Flush after every write, and the controller finds the
// flusher by unwrapping — a wrapper without Unwrap makes Flush fail, and the
// copy stops at the first event. That is the SSE counterpart of forwarding
// Hijacker for upgrades, and it is why the wrapper below implements it.
func TestSSE_MiddlewareCanRewriteStream(t *testing.T) {
	backend := sseBackend(t, "secret")

	proxy, proxyAddr := startSSEProxy(t, true, func(p *vtunnel.MITMProxy) {
		p.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(&rewritingWriter{ResponseWriter: w}, r)
			})
		})
	})
	proxy.ForwardTo("sse.test:443", backend.Listener.Addr().String())

	resp := sseGet(t, sseProxyClient(t, proxyAddr, false), "https://sse.test/v1/messages")
	defer resp.Body.Close()

	events, arrivals := collectSSELines(t, resp.Body, sseEventCount)

	// Rewritten on the way through...
	for i, line := range events {
		if strings.Contains(line, "secret") {
			t.Fatalf("event %d still carries the original payload: %q", i, line)
		}
		if !strings.Contains(line, "redacted") {
			t.Fatalf("event %d was not rewritten: %q", i, line)
		}
	}
	// ...without the stream collapsing into one batch.
	assertStreamed(t, arrivals)
}

// rewritingWriter redacts on the way out and forwards Unwrap so the proxy can
// still flush through it.
type rewritingWriter struct {
	http.ResponseWriter
}

func (w *rewritingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *rewritingWriter) Write(p []byte) (int, error) {
	replaced := bytes.ReplaceAll(p, []byte("secret"), []byte("redacted"))
	if _, err := w.ResponseWriter.Write(replaced); err != nil {
		return 0, err
	}
	// The caller is told it wrote what it handed over: the substitution changed
	// the bytes on the wire, not the amount of the body consumed.
	return len(p), nil
}

// collectSSELines is collectSSE plus the event text, for assertions about
// content rather than only timing.
func collectSSELines(t *testing.T, body io.Reader, want int) ([]string, []time.Duration) {
	t.Helper()

	start := time.Now()
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var lines []string
	var arrivals []time.Duration
	for scanner.Scan() {
		if line := scanner.Text(); strings.HasPrefix(line, "data:") {
			lines = append(lines, line)
			arrivals = append(arrivals, time.Since(start))
			if len(lines) == want {
				break
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read stream: %v", err)
	}
	if len(lines) != want {
		t.Fatalf("got %d events, want %d", len(lines), want)
	}
	return lines, arrivals
}
