package vtunnel_test

// What a CONNECT tunnel turns out to be carrying is decided once, from its
// opening bytes, and everything follows from that decision: terminate and
// inject, or pipe untouched. Getting it wrong is quiet in both directions — a
// stream that should have been piped is answered with 400, and a request that
// should have been injected into reaches the upstream without its credential
// and with nothing but a log line to say so.

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

// classifyProxy is an intercepting proxy with one cleartext route, optionally
// carrying a credential — which is what makes "was this terminated or piped"
// answerable from the upstream's side.
func classifyProxy(t *testing.T, domain, upstream string, opts ...vtunnel.ForwardOption) string {
	t.Helper()
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(generateTestCA(t)))
	if err := p.ForwardTo(domain, upstream, opts...); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(p.Close)
	return p.Addr().String()
}

// openTunnel opens a CONNECT tunnel and hands back the raw connection.
func openTunnel(t *testing.T, proxyAddr, authority string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("CONNECT %s: %v", authority, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT %s: %s", authority, resp.Status)
	}
	return conn, br
}

// authRecorder is an HTTP upstream that reports the credential it was given.
func authRecorder(t *testing.T) (addr string, seen chan string) {
	t.Helper()
	seen = make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case seen <- r.Header.Get("Authorization"):
		default:
		}
		fmt.Fprint(w, "upstream")
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), seen
}

// bannerServer speaks first, the way SMTP, IMAP, POP3, MySQL and postgres do,
// then echoes. Deciding what a tunnel carries by reading the client's opening
// bytes has nothing to read here — the client is waiting for this greeting.
func bannerServer(t *testing.T, banner string) (addr string, accepts *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	accepts = &atomic.Int32{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go func() {
				defer conn.Close()
				io.WriteString(conn, banner)
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String(), accepts
}

// A routed cleartext port whose server greets first must be piped, not waited
// on. The classification used to insist on three bytes from the client before
// deciding anything, so a protocol where the client's first move is to listen
// sat out the whole peek timeout and was then hung up on, with the upstream
// never dialled at all.
func TestServerFirstProtocolIsPipedNotWaitedOn(t *testing.T) {
	backend, accepts := bannerServer(t, "220 mail.corp ESMTP ready\r\n")
	proxyAddr := classifyProxy(t, "mail.corp:25", backend)

	start := time.Now()
	conn, br := openTunnel(t, proxyAddr, "mail.corp:25")

	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("no greeting after %v (upstream accepts: %d): %v", time.Since(start), accepts.Load(), err)
	}
	if line != "220 mail.corp ESMTP ready\r\n" {
		t.Fatalf("greeting = %q", line)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the greeting took %v to arrive", elapsed)
	}

	// And the tunnel works in both directions afterwards.
	fmt.Fprint(conn, "EHLO probe\r\n")
	if echoed, err := br.ReadString('\n'); err != nil || echoed != "EHLO probe\r\n" {
		t.Fatalf("echo = %q, %v", echoed, err)
	}
}

// The same rule for a client that does speak first, but says less than the
// classification wanted to read before making up its mind.
func TestShortFirstWriteIsPipedNotWaitedOn(t *testing.T) {
	backend, _ := bannerServer(t, "")
	proxyAddr := classifyProxy(t, "short.corp:9999", backend)

	conn, br := openTunnel(t, proxyAddr, "short.corp:9999")

	start := time.Now()
	fmt.Fprint(conn, "?")
	answer := make([]byte, 1)
	if _, err := io.ReadFull(br, answer); err != nil {
		t.Fatalf("a one-byte hello got no answer in %v: %v", time.Since(start), err)
	}
	if answer[0] != '?' {
		t.Fatalf("answer = %q", answer)
	}
}

// A request line may end in a bare LF. RFC 9112 §2.2 lets a recipient accept
// it, net/http's own parser does, and hand-rolled clients and shell scripts
// send it. Reading it as "not HTTP" turned a route that injects a credential
// into a byte pipe that does not, for a request the server behind it parses
// without complaint.
func TestBareLFRequestLineIsStillHTTP(t *testing.T) {
	upstream, seen := authRecorder(t)
	proxyAddr := classifyProxy(t, "api.corp:80", upstream,
		vtunnel.WithHeader("Authorization", "Bearer injected"))

	conn, br := openTunnel(t, proxyAddr, "api.corp:80")
	fmt.Fprint(conn, "GET /hello HTTP/1.1\nHost: api.corp\n\n")

	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("a bare-LF request line was not read as HTTP: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	select {
	case got := <-seen:
		if got != "Bearer injected" {
			t.Fatalf("upstream saw Authorization=%q, want the injected credential", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the request never reached the upstream")
	}
}

// TCP does not preserve write boundaries, and the sandbox router's tunnel hop
// re-segments whatever it carries. A request line that arrives in two pieces is
// the same request; classifying it from the first piece alone made the same
// client, sending the same bytes, injected into on one connection and piped on
// the next.
func TestSplitRequestLineIsStillHTTP(t *testing.T) {
	upstream, seen := authRecorder(t)
	proxyAddr := classifyProxy(t, "api.corp:80", upstream,
		vtunnel.WithHeader("Authorization", "Bearer injected"))

	conn, br := openTunnel(t, proxyAddr, "api.corp:80")
	fmt.Fprint(conn, "GET /hel")
	time.Sleep(150 * time.Millisecond)
	fmt.Fprint(conn, "lo HTTP/1.1\r\nHost: api.corp\r\n\r\n")

	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("a request line split across two writes was not read as HTTP: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	select {
	case got := <-seen:
		if got != "Bearer injected" {
			t.Fatalf("upstream saw Authorization=%q, want the injected credential", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the request never reached the upstream")
	}
}

// The rule that makes the two tests above safe to rely on: a route that carries
// a credential is never quietly downgraded to a pipe. Whatever this tunnel is,
// it is not something the credential can be added to, and a request that works
// without the credential it was configured to carry is worse than one that
// fails.
//
// The same rule already governs the other way interception can turn out to be
// impossible (an upstream that refuses it — see canFallBack); this is the
// remaining half.
func TestCredentialRouteIsNeverPipedInstead(t *testing.T) {
	backend, accepts := bannerServer(t, "")
	proxyAddr := classifyProxy(t, "db.corp:5432", backend,
		vtunnel.WithHeader("Authorization", "Bearer injected"))

	conn, br := openTunnel(t, proxyAddr, "db.corp:5432")

	// A postgres startup packet: a length, then a protocol version.
	conn.Write([]byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f})

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := br.Read(make([]byte, 64)); err == nil {
		t.Fatalf("the tunnel answered %d byte(s); it should have been closed", n)
	}
	if n := accepts.Load(); n != 0 {
		t.Fatalf("the upstream was dialled %d time(s): a route carrying a credential was "+
			"piped through untouched, so the request reached the upstream without it", n)
	}
}

// And the same stream on a route with no credential to lose still pipes, which
// is what makes postgres, redis and ssh work through a forwarded port.
func TestRouteWithoutCredentialStillPipes(t *testing.T) {
	backend, accepts := bannerServer(t, "")
	proxyAddr := classifyProxy(t, "db.corp:5432", backend)

	conn, _ := openTunnel(t, proxyAddr, "db.corp:5432")
	startup := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	conn.Write(startup)

	echoed := make([]byte, len(startup))
	if _, err := io.ReadFull(conn, echoed); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(echoed) != string(startup) || accepts.Load() != 1 {
		t.Fatalf("echo = %x, upstream accepts = %d", echoed, accepts.Load())
	}
}

// A handler route still has nowhere to pipe to, whatever it is handed.
func TestHandlerRouteStillRefusesNonHTTPStreams(t *testing.T) {
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(generateTestCA(t)))
	p.Handle("api.corp:5432", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "handled")
	}))
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	conn, br := openTunnel(t, p.Addr().String(), "api.corp:5432")
	conn.Write([]byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f})
	if _, err := io.ReadAll(br); err != nil {
		t.Fatalf("read: %v", err)
	}
}

// Interception itself must not regress: a TLS ClientHello inside the tunnel is
// still terminated, whatever the classification learned to tolerate.
func TestTLSInsideTunnelIsStillIntercepted(t *testing.T) {
	upstream, seen := authRecorder(t)
	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("api.corp", upstream,
		vtunnel.WithHeader("Authorization", "Bearer injected")); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	conn, _ := openTunnel(t, p.Addr().String(), "api.corp:443")
	tc := tls.Client(conn, &tls.Config{ServerName: "api.corp", RootCAs: caPoolFor(t, ca)})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("TLS handshake inside the tunnel: %v", err)
	}
	fmt.Fprint(tc, "GET / HTTP/1.1\r\nHost: api.corp\r\n\r\n")
	if _, err := http.ReadResponse(bufio.NewReader(tc), nil); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if got := <-seen; got != "Bearer injected" {
		t.Fatalf("upstream saw Authorization=%q", got)
	}
}

// A redis inline command is not an HTTP request, however much its first word
// looks like a method.
func TestInlineCommandIsNotMistakenForHTTP(t *testing.T) {
	backend, accepts := bannerServer(t, "")
	proxyAddr := classifyProxy(t, "cache.corp:6379", backend)

	conn, _ := openTunnel(t, proxyAddr, "cache.corp:6379")
	fmt.Fprint(conn, "GET mykey\r\n")

	echoed := make([]byte, len("GET mykey\r\n"))
	if _, err := io.ReadFull(conn, echoed); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(echoed) != "GET mykey\r\n" || accepts.Load() != 1 {
		t.Fatalf("echo = %q, accepts = %d: an inline command was read as HTTP",
			echoed, accepts.Load())
	}
}
