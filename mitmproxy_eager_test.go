package vtunnel_test

// When the client says nothing, who speaks first decides.
//
// A tunnel is classified from the client's opening bytes, and some protocols
// have none: in SMTP, IMAP, POP3, MySQL and postgres the server greets and the
// client answers. Waiting for a client that is itself waiting is a deadlock,
// and the only way out of it used to be a timeout — which means guessing, and
// the guess is wrong in both directions. Guess too early and a TLS client that
// was merely slow gets piped, losing interception with nothing to show for it;
// guess too late and every database connection starts seconds late.
//
// Dialling the upstream and letting it answer removes the guess. Silence from
// the client proves nothing, but a greeting from the server proves the protocol
// is server-first — which is mitmproxy's connection_strategy=eager, and its
// default.

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

// A server-first protocol starts as fast as the upstream answers, not as slowly
// as a timeout expires.
func TestServerFirstProtocolStartsAtOnce(t *testing.T) {
	backend, _ := bannerServer(t, "220 mail.corp ESMTP ready\r\n")
	proxyAddr := classifyProxy(t, "mail.corp:25", backend)

	start := time.Now()
	conn, br := openTunnel(t, proxyAddr, "mail.corp:25")

	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("no greeting: %v", err)
	}
	if line != "220 mail.corp ESMTP ready\r\n" {
		t.Fatalf("greeting = %q", line)
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("the greeting took %v to arrive; the upstream had it ready immediately, "+
			"so this is a timeout being waited out rather than a protocol being served", waited)
	}

	fmt.Fprint(conn, "EHLO probe\r\n")
	if echoed, err := br.ReadString('\n'); err != nil || echoed != "EHLO probe\r\n" {
		t.Fatalf("echo = %q, %v", echoed, err)
	}
}

// The other direction: a client that is slow to send its ClientHello is still
// intercepted. It is slow, not silent — and nothing about a TLS route's upstream
// says otherwise, because a TLS server has nothing to say until it is greeted.
func TestASlowTLSClientIsStillIntercepted(t *testing.T) {
	upstream, seen := authRecorder(t)
	ca := generateTestCA(t)

	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	// No headers, so this route may be piped — which is what makes the wrong
	// guess possible in the first place.
	if err := p.ForwardTo("api.corp", upstream); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	p.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Intercepted", "yes")
			next.ServeHTTP(w, r)
		})
	})
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	conn, _ := openTunnel(t, p.Addr().String(), "api.corp:443")
	// Longer than any grace period a guess could be built on.
	time.Sleep(4 * time.Second)

	tc := tls.Client(conn, &tls.Config{ServerName: "api.corp", RootCAs: caPoolFor(t, ca)})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("a client that paused before its ClientHello was not intercepted: %v", err)
	}
	fmt.Fprint(tc, "GET / HTTP/1.1\r\nHost: api.corp\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.Header.Get("X-Intercepted") != "yes" {
		t.Fatal("the connection was piped: the middleware never saw the request")
	}
	<-seen
}

// A client that speaks promptly costs no extra connection: there is nothing to
// find out by asking the upstream when the client has already said what this is.
func TestAPromptClientCostsNoExtraUpstreamConnection(t *testing.T) {
	backend, accepts := bannerServer(t, "")
	proxyAddr := classifyProxy(t, "db.corp:5432", backend)

	conn, _ := openTunnel(t, proxyAddr, "db.corp:5432")
	startup := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	conn.Write(startup)

	echoed := make([]byte, len(startup))
	if _, err := io.ReadFull(conn, echoed); err != nil {
		t.Fatalf("read: %v", err)
	}
	if n := accepts.Load(); n != 1 {
		t.Fatalf("the upstream was dialled %d times for one tunnel", n)
	}
}
