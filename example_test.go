package vtunnel_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/vivid-money/vtunnel"
)

// The sandbox side: a WebSocket endpoint for the controlplane to dial into, and
// a routing proxy for the application to point HTTPS_PROXY at. No CA and no
// credentials appear anywhere here — this side cannot decrypt.
func Example_sandbox() {
	// The same secret the controlplane dials in with, handed to this container
	// at launch by whatever created it.
	server := vtunnel.NewServer(vtunnel.WithServerSecret(os.Getenv("VTUNNEL_SECRET")))

	if err := server.StartProxy(":9090"); err != nil {
		log.Fatal(err)
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		server.HandleWebSocket(conn)
	})

	log.Fatal(http.ListenAndServe(":3001", nil))
}

// The controlplane side: dials into the sandbox and declares which domains it
// serves. The CA, the upstream addresses and the injected credentials all stay
// in this process.
func Example_controlplane() {
	caPEM, err := os.ReadFile("ca.pem")
	if err != nil {
		log.Fatal(err)
	}
	ca, err := vtunnel.LoadCA(caPEM)
	if err != nil {
		log.Fatal(err)
	}

	client := vtunnel.NewClient("ws://sandbox:3001/",
		vtunnel.WithSecret(os.Getenv("VTUNNEL_SECRET")),
		vtunnel.WithMitm(ca),
	)
	if err := client.Connect(); err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Routes are declared on the proxy; the client mirrors their domains into
	// the sandbox as they appear.
	routes := client.Proxy()

	// A private service, reached with a credential the sandbox never receives.
	routes.ForwardTo("api.corp", "localhost:8081",
		vtunnel.WithHeader("Authorization", "Bearer "+os.Getenv("API_TOKEN")))

	// Served from this process — no upstream connection, no second proxy.
	routes.Handle("mock.corp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello from the controlplane")
	}))

	// Straight through to the real host: TLS is never terminated, so this works
	// even against an upstream that pins certificates.
	routes.Forward("gitlab.corp")

	// Every subdomain to one service.
	routes.ForwardTo("*.preview.corp", "localhost:8082")

	select {} // serve until killed
}

// Routes can be changed while connected: the sandbox is re-synced after every
// change, so nothing else has to be called.
func ExampleMITMProxy_Remove() {
	client := vtunnel.NewClient("ws://sandbox:3001/")
	if err := client.Connect(); err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	client.Proxy().ForwardTo("api.corp", "localhost:8081")

	// Later: stop serving it. api.corp now egresses from the sandbox directly.
	client.Proxy().Remove("api.corp")
}

// Cross-cutting concerns — auth, audit, logging — attach once and wrap every
// request the proxy terminates, whether it is handled here or forwarded on.
func ExampleMITMProxy_Use() {
	proxy := vtunnel.NewMITMProxy()

	proxy.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("%s %s%s", r.Method, r.Host, r.URL.Path)
			next.ServeHTTP(w, r)
		})
	})

	// Refuse anything without a route, so a compromised sandbox cannot use this
	// as an open relay. The default is to dial the requested host directly.
	proxy.HandleUnmapped(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unknown domain", http.StatusForbidden)
	}))
}

// Raw TCP forwarding, with no HTTP or TLS handling: the server opens a port in
// the sandbox and pipes it to a local address.
func ExampleClient_Listen() {
	client := vtunnel.NewClient("ws://sandbox:3001/")
	if err := client.Connect(); err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Sandbox port 9000 reaches this machine's localhost:3000.
	if err := client.Listen(9000, "localhost:3000"); err != nil {
		log.Fatal(err)
	}

	// The client can terminate TLS on the way out.
	if err := client.Listen(8085, "tls://www.google.com:443"); err != nil {
		log.Fatal(err)
	}
}

// Generating a CA and extracting the half that may be installed in a sandbox.
func ExampleCACertPEM() {
	blob, err := vtunnel.GenerateCA("vtunnel MITM CA")
	if err != nil {
		log.Fatal(err)
	}
	// Keep the whole blob here: it contains the private key.
	if err := os.WriteFile("ca.pem", blob, 0o600); err != nil {
		log.Fatal(err)
	}

	// Ship only this to the sandbox trust store.
	certOnly, err := vtunnel.CACertPEM(blob)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("ca.crt", certOnly, 0o644); err != nil {
		log.Fatal(err)
	}
}

// A WebSocket is forwarded like any other route, and the credential configured
// for it lands in the handshake — the only HTTP request a WebSocket ever makes.
// After the upgrade the proxy splices the two connections and stops parsing, so
// subprotocols, compression and frame boundaries stay as the endpoints
// negotiated them.
func ExampleMITMProxy_ForwardTo_webSocket() {
	// The private service the sandbox is not allowed to hold credentials for.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen := r.Header.Get("Authorization")
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.WriteMessage(websocket.TextMessage, []byte("upstream saw "+seen))
	}))
	defer upstream.Close()

	// The CA stays on this side; a sandbox would trust only its certificate half.
	blob, err := vtunnel.GenerateCA("example CA")
	if err != nil {
		log.Fatal(err)
	}
	ca, err := vtunnel.LoadCA(blob)
	if err != nil {
		log.Fatal(err)
	}

	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		log.Fatal(err)
	}
	defer proxy.Close()

	proxy.ForwardTo("chat.corp:443", upstream.Listener.Addr().String(),
		vtunnel.WithHeader("Authorization", "Bearer from-the-controlplane"))

	// What the sandbox application does: dial wss:// through HTTPS_PROXY,
	// trusting the CA certificate installed in its store.
	conn, resp, err := (&websocket.Dialer{
		Proxy:           http.ProxyURL(exampleProxyURL(proxy)),
		TLSClientConfig: &tls.Config{RootCAs: exampleTrust(ca)},
	}).Dial("wss://chat.corp/socket", nil)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	resp.Body.Close()

	_, message, err := conn.ReadMessage()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(message))

	// Output:
	// upstream saw Bearer from-the-controlplane
}

// Middleware can rewrite a streaming response on its way through, which is how
// redaction or auditing of an LLM stream attaches without touching any route.
//
// A wrapper must implement Unwrap: incremental delivery depends on the proxy
// flushing after every write, and http.ResponseController finds the flusher by
// unwrapping. Without it the client would receive only the first event.
func ExampleMITMProxy_Use_serverSentEvents() {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		rc := http.NewResponseController(w)
		for i := range 3 {
			fmt.Fprintf(w, "data: account 4111-1111-%04d\n\n", i)
			rc.Flush()
		}
	}))
	defer upstream.Close()

	blob, _ := vtunnel.GenerateCA("example CA")
	ca, _ := vtunnel.LoadCA(blob)

	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	proxy.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(&redactingWriter{ResponseWriter: w}, r)
		})
	})
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		log.Fatal(err)
	}
	defer proxy.Close()

	proxy.ForwardTo("llm.corp:443", upstream.Listener.Addr().String())

	resp, err := exampleClient(proxy, ca).Get("https://llm.corp/v1/messages")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if line := scanner.Text(); line != "" {
			fmt.Println(line)
		}
	}

	// Output:
	// data: account [redacted]
	// data: account [redacted]
	// data: account [redacted]
}

// redactingWriter rewrites the body on its way to the client. Unwrap is what
// keeps the stream incremental; see ExampleMITMProxy_Use_serverSentEvents.
type redactingWriter struct {
	http.ResponseWriter
}

func (w *redactingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *redactingWriter) Write(p []byte) (int, error) {
	cleaned := regexp.MustCompile(`4111-1111-\d{4}`).ReplaceAll(p, []byte("[redacted]"))
	if _, err := w.ResponseWriter.Write(cleaned); err != nil {
		return 0, err
	}
	// The caller is told it wrote everything it handed over: the substitution
	// changed the bytes on the wire, not how much of the body was consumed.
	return len(p), nil
}

// Shutdown lets requests already in flight finish before the proxy stops, and
// gives up at the deadline. Close is the immediate counterpart: it drops
// everything, including connections mid-response.
//
// A byte pipe and an open stream have no request boundary to wait for, so those
// are only ever ended by the deadline. Give the context a bound you are willing
// to wait for.
func ExampleMITMProxy_Shutdown() {
	blob, _ := vtunnel.GenerateCA("example CA")
	ca, _ := vtunnel.LoadCA(blob)

	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		log.Fatal(err)
	}

	started := make(chan struct{})
	proxy.Handle("slow.corp:443", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		time.Sleep(200 * time.Millisecond)
		fmt.Fprint(w, "finished")
	}))

	body := make(chan string, 1)
	go func() {
		resp, err := exampleClient(proxy, ca).Get("https://slow.corp/")
		if err != nil {
			body <- "request failed: " + err.Error()
			return
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		body <- string(out)
	}()

	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fmt.Println("shutdown error:", proxy.Shutdown(ctx))
	fmt.Println("in-flight response:", <-body)

	// Output:
	// shutdown error: <nil>
	// in-flight response: finished
}

// Some upstreams cannot be intercepted at all: a client that pins certificates
// refuses the generated leaf every time, and an upstream demanding mutual TLS
// refuses the proxy every time. The proxy learns this on its own and pipes those
// domains through untouched for a while, but a domain known to pin can be
// declared up front so not even the first request is spent discovering it.
//
// Nothing is injected into a domain served this way — there is no decrypted
// request to inject into.
func ExampleMITMProxy_MITMExceptions() {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello from the real upstream")
	}))
	defer upstream.Close()

	blob, _ := vtunnel.GenerateCA("example CA")
	ca, _ := vtunnel.LoadCA(blob)

	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		log.Fatal(err)
	}
	defer proxy.Close()

	proxy.ForwardTo("pinned.corp:443", upstream.Listener.Addr().String())
	proxy.MITMExceptions("pinned.corp")

	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(exampleProxyURL(proxy)),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err := client.Get("https://pinned.corp/")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	out, _ := io.ReadAll(resp.Body)
	fmt.Println(string(out))
	// The certificate the client saw is the upstream's own, not one this proxy
	// minted: nothing was terminated in between.
	fmt.Println("issued by the MITM CA:", resp.TLS.PeerCertificates[0].Issuer.CommonName == "example CA")

	// Output:
	// hello from the real upstream
	// issued by the MITM CA: false
}

// --- helpers shared by the examples above ---

func exampleProxyURL(p *vtunnel.MITMProxy) *url.URL {
	u, err := url.Parse("http://" + p.Addr().String())
	if err != nil {
		log.Fatal(err)
	}
	return u
}

// exampleTrust builds the trust store a sandbox would get from ca.crt.
func exampleTrust(ca tls.Certificate) *x509.CertPool {
	leaf, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return pool
}

func exampleClient(p *vtunnel.MITMProxy, ca tls.Certificate) *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(exampleProxyURL(p)),
			TLSClientConfig: &tls.Config{RootCAs: exampleTrust(ca)},
		},
	}
}

// Frames of a spliced WebSocket can be observed without the proxy terminating
// it. Use wraps the upgrade too, so middleware that hands down a ResponseWriter
// whose Hijack returns wrapped connections sees every byte. One connection
// carries both directions: reads are what the client sent, writes are what it
// received.
//
// Note the second wrapper. Hijack returns a connection *and* a bufio.ReadWriter,
// and the proxy reads through the latter — wrapping only the connection would
// show writes and silently miss every read.
func ExampleMITMProxy_Use_webSocketTap() {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			kind, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			conn.WriteMessage(kind, msg)
		}
	}))
	defer upstream.Close()

	blob, _ := vtunnel.GenerateCA("example CA")
	ca, _ := vtunnel.LoadCA(blob)

	var mu sync.Mutex
	sent, received := 0, 0

	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	proxy.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(&wsTapWriter{
				ResponseWriter: w,
				onRead:         func([]byte) { mu.Lock(); sent++; mu.Unlock() },
				onWrite:        func([]byte) { mu.Lock(); received++; mu.Unlock() },
			}, r)
		})
	})
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		log.Fatal(err)
	}
	defer proxy.Close()

	proxy.ForwardTo("chat.corp:443", upstream.Listener.Addr().String())

	conn, resp, err := (&websocket.Dialer{
		Proxy:           http.ProxyURL(exampleProxyURL(proxy)),
		TLSClientConfig: &tls.Config{RootCAs: exampleTrust(ca)},
	}).Dial("wss://chat.corp/socket", nil)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	resp.Body.Close()

	conn.WriteMessage(websocket.TextMessage, []byte("ping"))
	conn.ReadMessage()

	mu.Lock()
	defer mu.Unlock()
	fmt.Println("saw traffic in both directions:", sent > 0 && received > 0)

	// Output:
	// saw traffic in both directions: true
}

// Changing frames rather than only watching them is the same hook plus a frame
// codec, which the proxy deliberately does not provide: parsing frames means
// deciding what to do about compression, fragmentation and control frames, and
// most callers want none of that.
//
// The rewriter below is the smallest thing that works and is honest about its
// limits: it only touches unfragmented text frames coming from the server, and
// only substitutes text of equal length, so no frame header has to be rebuilt. A
// real implementation needs a proper codec — and must strip permessage-deflate
// from the handshake first, or the payloads it inspects are compressed bytes.
func ExampleMITMProxy_Use_webSocketRewrite() {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.WriteMessage(websocket.TextMessage, []byte("the password is hunter2"))
	}))
	defer upstream.Close()

	blob, _ := vtunnel.GenerateCA("example CA")
	ca, _ := vtunnel.LoadCA(blob)

	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	proxy.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(&wsTapWriter{
				ResponseWriter: w,
				rewriteWrite:   func(b []byte) []byte { return rewriteTextFrame(b, "hunter2", "*******") },
			}, r)
		})
	})
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		log.Fatal(err)
	}
	defer proxy.Close()

	proxy.ForwardTo("chat.corp:443", upstream.Listener.Addr().String())

	conn, resp, err := (&websocket.Dialer{
		Proxy:           http.ProxyURL(exampleProxyURL(proxy)),
		TLSClientConfig: &tls.Config{RootCAs: exampleTrust(ca)},
	}).Dial("wss://chat.corp/socket", nil)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	resp.Body.Close()

	_, message, err := conn.ReadMessage()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(message))

	// Output:
	// the password is *******
}

// rewriteTextFrame substitutes equal-length text inside a single unfragmented,
// unmasked text frame — the shape a server sends. Anything else is passed
// through untouched. See ExampleMITMProxy_Use_webSocketRewrite for why this is
// deliberately minimal.
func rewriteTextFrame(frame []byte, from, to string) []byte {
	const (
		finTextFrame = 0x81 // FIN set, opcode 1
		maskBit      = 0x80
		shortLenMax  = 125 // above this the length field grows
	)
	if len(from) != len(to) || len(frame) < 2 {
		return frame
	}
	if frame[0] != finTextFrame || frame[1]&maskBit != 0 || frame[1] > shortLenMax {
		return frame
	}
	header, payload := 2, int(frame[1])
	if len(frame) != header+payload {
		return frame
	}
	out := append([]byte(nil), frame...)
	copy(out[header:], bytes.ReplaceAll(out[header:], []byte(from), []byte(to)))
	return out
}

// wsTapWriter hands the proxy connections that report, and optionally rewrite,
// what passes through them. Both wrappers matter: see
// ExampleMITMProxy_Use_webSocketTap.
type wsTapWriter struct {
	http.ResponseWriter
	onRead       func([]byte)
	onWrite      func([]byte)
	rewriteWrite func([]byte) []byte
}

func (w *wsTapWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *wsTapWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, brw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	tapped := &wsTapConn{Conn: conn, onRead: w.onRead, onWrite: w.onWrite, rewrite: w.rewriteWrite}

	// Carry across anything net/http already buffered, then read through the tap.
	var src io.Reader = tapped
	if n := brw.Reader.Buffered(); n > 0 {
		head, _ := brw.Reader.Peek(n)
		src = io.MultiReader(bytes.NewReader(append([]byte(nil), head...)), tapped)
	}
	return tapped, bufio.NewReadWriter(bufio.NewReader(src), bufio.NewWriter(tapped)), nil
}

type wsTapConn struct {
	net.Conn
	onRead  func([]byte)
	onWrite func([]byte)
	rewrite func([]byte) []byte
}

func (c *wsTapConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && c.onRead != nil {
		c.onRead(p[:n])
	}
	return n, err
}

func (c *wsTapConn) Write(p []byte) (int, error) {
	if c.onWrite != nil {
		c.onWrite(p)
	}
	out := p
	if c.rewrite != nil {
		out = c.rewrite(p)
	}
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Because the proxy splices the connection instead of re-terminating the
// WebSocket, the subprotocol and any extensions are negotiated between the
// endpoints themselves. A proxy that terminated the socket would have to
// re-negotiate both, and would in practice drop compression.
func ExampleMITMProxy_ForwardTo_webSocketNegotiation() {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{
			Subprotocols:      []string{"v2.chat"},
			EnableCompression: true,
		}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		conn.Close()
	}))
	defer upstream.Close()

	blob, _ := vtunnel.GenerateCA("example CA")
	ca, _ := vtunnel.LoadCA(blob)

	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		log.Fatal(err)
	}
	defer proxy.Close()

	proxy.ForwardTo("chat.corp:443", upstream.Listener.Addr().String())

	conn, resp, err := (&websocket.Dialer{
		Proxy:             http.ProxyURL(exampleProxyURL(proxy)),
		TLSClientConfig:   &tls.Config{RootCAs: exampleTrust(ca)},
		Subprotocols:      []string{"v2.chat", "v1.chat"},
		EnableCompression: true,
	}).Dial("wss://chat.corp/socket", nil)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	defer resp.Body.Close()

	fmt.Println("subprotocol:", conn.Subprotocol())
	fmt.Println("compression negotiated:",
		strings.Contains(resp.Header.Get("Sec-WebSocket-Extensions"), "permessage-deflate"))

	// Output:
	// subprotocol: v2.chat
	// compression negotiated: true
}

// gRPC reports its status in HTTP trailers, which arrive after the body and
// therefore have to be forwarded separately from the headers. A proxy that
// copies only headers and body turns every call into one with no status.
func ExampleMITMProxy_ForwardTo_grpcTrailers() {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The unannounced form: the name is not known until the body is done.
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
		fmt.Fprint(w, "response body")
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()

	blob, _ := vtunnel.GenerateCA("example CA")
	ca, _ := vtunnel.LoadCA(blob)

	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	// Trust the upstream's own certificate on the proxy's leg of the connection.
	proxy.SetTransportTLSConfig(&tls.Config{RootCAs: upstreamTrust(upstream)})
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		log.Fatal(err)
	}
	defer proxy.Close()

	proxy.ForwardTo("grpc.corp:443", "tls://"+upstream.Listener.Addr().String())

	client := &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(exampleProxyURL(proxy)),
		TLSClientConfig:   &tls.Config{RootCAs: exampleTrust(ca)},
		ForceAttemptHTTP2: true,
	}}
	resp, err := client.Get("https://grpc.corp/echo")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body) // trailers are only readable once the body is drained
	fmt.Println("body:", string(body))
	fmt.Println("grpc-status:", resp.Trailer.Get("Grpc-Status"))

	// Output:
	// body: response body
	// grpc-status: 0
}

func upstreamTrust(s *httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	return pool
}
