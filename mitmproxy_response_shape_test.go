package vtunnel_test

// What the client is told, and when. Each of these is a case where the proxy
// answered differently from the upstream it was standing in for.

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

// rawUpstream answers every connection with a fixed script, so a test can shape
// a response net/http would not produce.
func rawUpstream(t *testing.T, serve func(conn net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				serve(conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// A streaming response is an answer whose head arrives long before its body: a
// model that thinks for half a minute before its first token, a long poll, an
// event stream with nothing to report yet. Holding the head back until the first
// body byte leaves the client with nothing at all — not even a status line — so
// a response-header timeout fires on a request the upstream is serving
// correctly, and the failure looks like the upstream's.
func TestResponseHeadReachesTheClientBeforeTheBody(t *testing.T) {
	const bodyDelay = 700 * time.Millisecond
	upstream := rawUpstream(t, func(conn net.Conn) {
		br := bufio.NewReader(conn)
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"+
			"Transfer-Encoding: chunked\r\n\r\n")
		time.Sleep(bodyDelay)
		io.WriteString(conn, "7\r\ndata: 1\r\n0\r\n\r\n")
	})

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("api.corp", upstream); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	tc := connectThenTLS(t, p.Addr().String(), "api.corp:443", "api.corp", "", ca)
	start := time.Now()
	fmt.Fprint(tc, "GET / HTTP/1.1\r\nHost: api.corp\r\n\r\n")

	br := bufio.NewReader(tc)
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if waited := time.Since(start); waited > bodyDelay/2 {
		t.Fatalf("the status line took %v to arrive, and the upstream had it ready "+
			"immediately: the head is being held until the first body byte", waited)
	}
}

// `OPTIONS *` asks about the server, not about a resource, and it is the correct
// form inside an intercepted connection. net/http answers it itself unless told
// not to, so it never reached a route, a credential or an upstream — the proxy
// reported healthy on its own behalf for a domain it could not even resolve.
func TestOptionsAsteriskReachesTheUpstream(t *testing.T) {
	var got string
	upstream := rawUpstream(t, func(conn net.Conn) {
		br := bufio.NewReader(conn)
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		got = strings.TrimSpace(line)
		io.WriteString(conn, "HTTP/1.1 204 No Content\r\nAllow: GET, OPTIONS\r\n\r\n")
	})

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("api.corp", upstream); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	tc := connectThenTLS(t, p.Addr().String(), "api.corp:443", "api.corp", "", ca)
	fmt.Fprint(tc, "OPTIONS * HTTP/1.1\r\nHost: api.corp\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()

	if got != "OPTIONS * HTTP/1.1" {
		t.Fatalf("the upstream saw %q, want the asterisk-form request: net/http answered "+
			"it in the proxy's place", got)
	}
	if resp.Header.Get("Allow") != "GET, OPTIONS" {
		t.Fatalf("client saw Allow=%q, want the upstream's answer", resp.Header.Get("Allow"))
	}
}

// A request with no Host names no destination. Synthesising one produced ":80",
// which in Go is a dialable address meaning the local machine — so a request
// nobody could route became a connection to the proxy's own loopback.
func TestRequestWithoutHostIsRefusedRatherThanInvented(t *testing.T) {
	p := vtunnel.NewMITMProxy()
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	conn, err := net.DialTimeout("tcp", p.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	fmt.Fprint(conn, "GET /secret HTTP/1.0\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %s, want 400: a request with no Host has no destination "+
			"to dial, so the proxy must say so rather than invent one", resp.Status)
	}
}

// A client that asks for trailers over HTTP/1.1 is asking the origin, not the
// proxy. TE is hop-by-hop, so the proxy has to re-state it — and it was
// re-stating it only for HTTP/2 clients, which meant an HTTP/1.1 client's
// request for trailers was deleted on the way and the origin sent none.
func TestTETrailersSurvivesForHTTP11Clients(t *testing.T) {
	seen := make(chan []string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case seen <- r.Header.Values("Te"):
		default:
		}
		fmt.Fprint(w, "ok")
	}))
	defer backend.Close()

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("api.corp", backend.Listener.Addr().String()); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	tc := connectThenTLS(t, p.Addr().String(), "api.corp:443", "api.corp", "", ca)
	fmt.Fprint(tc, "GET / HTTP/1.1\r\nHost: api.corp\r\nTE: trailers\r\n\r\n")
	if _, err := http.ReadResponse(bufio.NewReader(tc), nil); err != nil {
		t.Fatalf("read response: %v", err)
	}

	if got := <-seen; len(got) != 1 || !strings.EqualFold(strings.TrimSpace(got[0]), "trailers") {
		t.Fatalf("upstream saw TE=%v, want [trailers]", got)
	}
}

// Anything else in TE is genuinely hop-by-hop and stays here: it describes
// transfer codings this hop would have to apply, not something to ask the
// origin for.
func TestTETransferCodingIsStillStripped(t *testing.T) {
	seen := make(chan []string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case seen <- r.Header.Values("Te"):
		default:
		}
		fmt.Fprint(w, "ok")
	}))
	defer backend.Close()

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("api.corp", backend.Listener.Addr().String()); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	tc := connectThenTLS(t, p.Addr().String(), "api.corp:443", "api.corp", "", ca)
	fmt.Fprint(tc, "GET / HTTP/1.1\r\nHost: api.corp\r\nTE: deflate\r\n\r\n")
	if _, err := http.ReadResponse(bufio.NewReader(tc), nil); err != nil {
		t.Fatalf("read response: %v", err)
	}

	if got := <-seen; len(got) != 0 {
		t.Fatalf("upstream saw TE=%v, want it stripped", got)
	}
}

// A 101 the client did not ask for cannot be acted on: the proxy has already
// decided this is an ordinary response, so nothing is spliced, the upstream's
// bytes after it are never relayed, and the client is left holding a connection
// that will never say anything again. Answering 502 at least ends it.
func TestUnrequested101DoesNotWedgeTheClient(t *testing.T) {
	upstream := rawUpstream(t, func(conn net.Conn) {
		br := bufio.NewReader(conn)
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"+
			"Connection: Upgrade\r\n\r\nRAWFRAMES")
		time.Sleep(time.Second)
	})

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("api.corp", upstream); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	tc := connectThenTLS(t, p.Addr().String(), "api.corp:443", "api.corp", "", ca)
	tc.SetDeadline(time.Now().Add(5 * time.Second))
	// An ordinary request: no Upgrade, so nothing about this asked to switch.
	fmt.Fprint(tc, "GET / HTTP/1.1\r\nHost: api.corp\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.Fatal("the client was handed a 101 it never asked for, with nothing following it: " +
			"the connection is now unusable and the request will never complete")
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %s, want 502", resp.Status)
	}
}

// An HTTP/2 server hands its handler a non-nil body even for a request that
// ended on HEADERS, so a bodyless request re-issued as it stands has an unknown
// outgoing length. Three things follow, all of them wrong: an HTTP/1 upstream
// is sent chunked framing with no Content-Length, an HTTP/2 one gets an extra
// empty DATA frame instead of END_STREAM on the headers, and net/http refuses
// to retry the request at all — so an h2 client loses the ordinary race with an
// upstream's idle timeout and gets a 502 where an h1 client got a retry.
func TestBodylessRequestFromAnH2ClientIsNotChunked(t *testing.T) {
	framing := make(chan string, 4)
	upstream := rawUpstream(t, func(conn net.Conn) {
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if req.Method == "PRI" {
			return // the h2c probe, not a request
		}
		io.Copy(io.Discard, req.Body)
		select {
		case framing <- fmt.Sprintf("TE=%v CL=%d", req.TransferEncoding, req.ContentLength):
		default:
		}
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("api.corp", upstream); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	client := proxyClientFor(t, p.Addr().String(), ca)
	client.Transport.(*http.Transport).ForceAttemptHTTP2 = true

	req, _ := http.NewRequest(http.MethodPost, "https://api.corp/x", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.Proto != "HTTP/2.0" {
		t.Skipf("client negotiated %s, not h2; nothing to check here", resp.Proto)
	}

	if got := <-framing; got != "TE=[] CL=0" {
		t.Fatalf("the upstream saw %s, want TE=[] CL=0: a request with no body was "+
			"forwarded as one of unknown length", got)
	}
}
