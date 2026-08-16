package vtunnel_test

import (
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

// Content-Encoding is where a re-issuing proxy can quietly corrupt a response.
// The proxy does not pipe bytes on a terminated route: it re-issues the request
// with its own http.Transport, and that transport has opinions about compression.
// When the incoming request carries no Accept-Encoding, Transport adds one,
// transparently decompresses the answer and strips Content-Encoding along with
// Content-Length. When the request does carry one, Transport stays out of the way
// and the compressed bytes must survive the copy verbatim.
//
// Both outcomes are correct, but only if the response headers agree with the body
// that actually reaches the client. A proxy that forwards Content-Encoding: gzip
// while handing over decompressed bytes produces a body no client can read.
//
// go-mitmproxy sidesteps the question by setting DisableCompression: true on every
// transport it builds, so it always sees and forwards the original bytes. These
// tests establish what our behaviour actually is before deciding whether to
// follow it.

const gzipPayload = "vtunnel gzip payload — compressible enough to be worth it. "

// TestGzip_PassthroughWhenClientAsks covers the common case: the application sets
// its own Accept-Encoding, so the proxy's transport must not interfere. The client
// has to receive the compressed bytes with Content-Encoding intact.
func TestGzip_PassthroughWhenClientAsks(t *testing.T) {
	want := strings.Repeat(gzipPayload, 200)
	backend := gzipBackend(t, want)

	proxy, proxyAddr := startSSEProxy(t, true, nil)
	proxy.ForwardTo("gz.test:443", backend.Listener.Addr().String())

	resp := gzipGet(t, sseProxyClient(t, proxyAddr, false), "https://gz.test/", true)
	defer resp.Body.Close()

	if enc := resp.Header.Get("Content-Encoding"); enc != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip — the proxy dropped the encoding header", enc)
	}
	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatalf("body is not gzip despite Content-Encoding: gzip: %v", err)
	}
	defer gr.Close()
	body, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if string(body) != want {
		t.Fatalf("body mismatch: got %d bytes, want %d", len(body), len(want))
	}
}

// TestGzip_TransparentWhenClientSilent covers the other branch: the application
// sends no Accept-Encoding, so the proxy's own transport asks for gzip and
// decompresses. What reaches the client must then be plain bytes with no
// Content-Encoding claiming otherwise.
//
// Reaching this branch takes care. A stock http.Client adds Accept-Encoding: gzip
// itself and decompresses on the way back, which would make the assertions below
// pass without the proxy ever being involved — so the test client has
// DisableCompression set, and a middleware asserts that the request really did
// arrive at the proxy with no Accept-Encoding on it.
func TestGzip_TransparentWhenClientSilent(t *testing.T) {
	want := strings.Repeat(gzipPayload, 200)
	backend := gzipBackend(t, want)

	seen := make(chan string, 1)
	proxy, proxyAddr := startSSEProxy(t, true, func(p *vtunnel.MITMProxy) {
		p.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case seen <- r.Header.Get("Accept-Encoding"):
				default:
				}
				next.ServeHTTP(w, r)
			})
		})
	})
	proxy.ForwardTo("gz.test:443", backend.Listener.Addr().String())

	resp := gzipGet(t, gzipRawClient(t, proxyAddr), "https://gz.test/", false)
	defer resp.Body.Close()

	select {
	case got := <-seen:
		if got != "" {
			t.Fatalf("proxy received Accept-Encoding: %q — the client asked for compression, "+
				"so this exercises passthrough, not the proxy's transparent path", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("middleware never saw the request")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		t.Fatalf("Content-Encoding = %q on a body of %d bytes — header and body disagree", enc, len(body))
	}
	if string(body) != want {
		t.Fatalf("body mismatch: got %d bytes, want %d", len(body), len(want))
	}
}

// TestGzip_HTTP2Client repeats the passthrough case over h2, where the response is
// written through an http2 ResponseWriter instead of an HTTP/1.1 one.
func TestGzip_HTTP2Client(t *testing.T) {
	want := strings.Repeat(gzipPayload, 200)
	backend := gzipBackend(t, want)

	proxy, proxyAddr := startSSEProxy(t, true, nil)
	proxy.ForwardTo("gz.test:443", backend.Listener.Addr().String())

	resp := gzipGet(t, sseProxyClient(t, proxyAddr, true), "https://gz.test/", true)
	defer resp.Body.Close()

	if resp.ProtoMajor != 2 {
		t.Fatalf("client protocol = HTTP/%d, want HTTP/2", resp.ProtoMajor)
	}
	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatalf("body is not gzip: %v", err)
	}
	defer gr.Close()
	body, _ := io.ReadAll(gr)
	if string(body) != want {
		t.Fatalf("body mismatch: got %d bytes, want %d", len(body), len(want))
	}
}

// TestGzip_SSEStillStreams is the combination that would hurt in production: a
// compressed event stream. Compression adds a second buffer between the upstream
// and the client, so the proxy streaming correctly is necessary but not sufficient
// — the gzip layer has to be flushed per event too. This pins down that our copy
// path does not add buffering of its own on top.
func TestGzip_SSEStillStreams(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)

		rc := http.NewResponseController(w)
		gw := gzip.NewWriter(w)
		defer gw.Close()

		for i := range sseEventCount {
			if _, err := fmt.Fprintf(gw, "data: gz-%d\n\n", i); err != nil {
				return
			}
			// Both layers must be flushed: gzip's own buffer, then the socket.
			if err := gw.Flush(); err != nil {
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
	}))
	t.Cleanup(backend.Close)

	proxy, proxyAddr := startSSEProxy(t, true, nil)
	proxy.ForwardTo("gz.test:443", backend.Listener.Addr().String())

	resp := gzipGet(t, sseProxyClient(t, proxyAddr, false), "https://gz.test/v1/messages", true)
	defer resp.Body.Close()

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatalf("body is not gzip: %v", err)
	}
	defer gr.Close()

	assertStreamed(t, collectSSE(t, gr, sseEventCount))
}

// TestGzip_RawPipe covers the untouched path for contrast: with no CA nothing is
// parsed, so compression is simply not the proxy's business.
func TestGzip_RawPipe(t *testing.T) {
	want := strings.Repeat(gzipPayload, 200)

	backend := httptest.NewUnstartedServer(gzipHandler(t, want))
	backend.StartTLS()
	t.Cleanup(backend.Close)

	proxy, proxyAddr := startSSEProxy(t, false, nil)
	proxy.ForwardTo("gz.test:443", backend.Listener.Addr().String())

	resp := gzipGet(t, sseProxyClient(t, proxyAddr, false), "https://gz.test/", true)
	defer resp.Body.Close()

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatalf("body is not gzip: %v", err)
	}
	defer gr.Close()
	body, _ := io.ReadAll(gr)
	if string(body) != want {
		t.Fatalf("body mismatch: got %d bytes, want %d", len(body), len(want))
	}
}

// --- helpers ---

// gzipHandler serves body gzipped, announcing it the way a real server would.
func gzipHandler(t *testing.T, body string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			// Nobody asked for compression; answer in plain text so the test can
			// tell the two branches apart by what actually arrives.
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, body)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)

		gw := gzip.NewWriter(w)
		defer gw.Close()
		io.WriteString(gw, body)
	}
}

// gzipRawClient talks to the proxy without any transport-level compression of its
// own, so whatever Accept-Encoding the test sets (or omits) is what the proxy sees,
// and whatever body comes back is what the proxy actually sent.
func gzipRawClient(t *testing.T, proxyAddr string) *http.Client {
	t.Helper()
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:              http.ProxyURL(mustParseURL(t, "http://"+proxyAddr)),
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
			DisableCompression: true,
		},
	}
}

func gzipBackend(t *testing.T, body string) *httptest.Server {
	t.Helper()
	backend := httptest.NewServer(gzipHandler(t, body))
	t.Cleanup(backend.Close)
	return backend
}

// gzipGet issues a GET, optionally setting Accept-Encoding explicitly. Setting it
// is what stops both the proxy's transport and the test client's own transport
// from decompressing behind our back, which is the only way to observe the wire.
func gzipGet(t *testing.T, c *http.Client, rawURL string, askGzip bool) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if askGzip {
		req.Header.Set("Accept-Encoding", "gzip")
	}

	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("GET %s: status %d", rawURL, resp.StatusCode)
	}
	return resp
}
