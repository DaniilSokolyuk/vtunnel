package vtunnel_test

// What a configured header does to the request the upstream finally sees.

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

// requestRecorder reports the raw request line and headers the upstream got, so
// framing questions — one header line or two — can be asked directly.
func requestRecorder(t *testing.T) (addr string, got chan string) {
	t.Helper()
	got = make(chan string, 4)
	srv := rawUpstream(t, func(conn net.Conn) {
		br := bufio.NewReader(conn)
		// Answer a ClientHello the way any cleartext HTTP server does: this is
		// not HTTP, so hang up rather than wait for a request line that is
		// never coming.
		if first, err := br.Peek(1); err != nil || first[0] == 0x16 {
			return
		}
		var head strings.Builder
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			head.WriteString(line)
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		select {
		case got <- head.String():
		default:
		}
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	return srv, got
}

func injectingProxy(t *testing.T, upstream string, opts ...vtunnel.ForwardOption) (string, func(string) string) {
	t.Helper()
	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("api.corp", upstream, opts...); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(p.Close)

	return p.Addr().String(), func(request string) string {
		tc := connectThenTLS(t, p.Addr().String(), "api.corp:443", "api.corp", "", ca)
		fmt.Fprint(tc, request)
		resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.Status
	}
}

// Cookie is additive in the protocol and singular on the wire: RFC 6265 §5.4
// says a user agent must not send more than one Cookie line, and the pairs are
// joined with "; ". Treating it like any other header produced one line per
// configured value, and replaced whatever cookies the application was carrying
// with the injected one.
func TestCookieInjectionMergesWithTheClientsOwn(t *testing.T) {
	upstream, got := requestRecorder(t)
	_, send := injectingProxy(t, upstream,
		vtunnel.WithHeader("Cookie", "sess=abc"),
		vtunnel.WithHeader("Cookie", "csrf=xyz"))

	send("GET / HTTP/1.1\r\nHost: api.corp\r\nCookie: app=own\r\n\r\n")

	select {
	case head := <-got:
		lines := 0
		var value string
		for _, line := range strings.Split(head, "\r\n") {
			if after, ok := strings.CutPrefix(line, "Cookie: "); ok {
				lines++
				value = after
			}
		}
		if lines != 1 {
			t.Fatalf("%d Cookie header lines, want exactly one:\n%s", lines, head)
		}
		for _, pair := range []string{"app=own", "sess=abc", "csrf=xyz"} {
			if !strings.Contains(value, pair) {
				t.Errorf("Cookie = %q, missing %q", value, pair)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the request never reached the upstream")
	}
}

// Host is not an ordinary header — net/http keeps it in a field of its own, so
// writing it into the header map did nothing at all, silently. A route pointed
// at a virtual-hosted internal target had no way to name the vhost, and the one
// API that looks like it should was accepted without complaint.
func TestHostInjectionReachesTheUpstream(t *testing.T) {
	upstream, got := requestRecorder(t)
	_, send := injectingProxy(t, upstream, vtunnel.WithHeader("Host", "vhost.internal"))

	send("GET /x HTTP/1.1\r\nHost: api.corp\r\n\r\n")

	select {
	case head := <-got:
		if !strings.Contains(head, "Host: vhost.internal") {
			t.Fatalf("the upstream saw:\n%s\nwant Host: vhost.internal", head)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the request never reached the upstream")
	}
}

// Injecting Host must not weaken the check that keeps a sandbox from aiming an
// injected credential at another virtual host: that check reads what the client
// claimed, before anything is injected.
func TestHostInjectionDoesNotWeakenTheAuthorityCheck(t *testing.T) {
	upstream, _ := requestRecorder(t)
	_, send := injectingProxy(t, upstream, vtunnel.WithHeader("Host", "vhost.internal"))

	if status := send("GET /x HTTP/1.1\r\nHost: other.corp\r\n\r\n"); !strings.HasPrefix(status, "421") {
		t.Fatalf("status = %s, want 421 for a Host that is not the connection authority", status)
	}
}

// The sandbox writes the request; the controlplane attaches the credential that
// makes it trusted. Between them that is enough to tell an internal service
// both "this is authorised" and "it came from wherever I say" — because
// X-Forwarded-For and its relatives are claims, and internal services routinely
// believe them: rate limits, address allowlists, audit trails.
//
// This proxy is not a hop those claims travelled through. It is the first hop,
// and the thing in front of it is untrusted, so whatever it says about origin
// does not go on to the upstream.
func TestClaimedOriginHeadersDoNotReachTheUpstream(t *testing.T) {
	upstream, got := requestRecorder(t)
	_, send := injectingProxy(t, upstream, vtunnel.WithHeader("Authorization", "Bearer injected"))

	send("GET /x HTTP/1.1\r\nHost: api.corp\r\n" +
		"X-Forwarded-For: 10.0.0.1\r\n" +
		"X-Forwarded-Host: admin.corp\r\n" +
		"X-Forwarded-Proto: https\r\n" +
		"X-Real-Ip: 10.0.0.1\r\n" +
		"Forwarded: for=10.0.0.1;host=admin.corp\r\n" +
		"X-Client-Ip: 10.0.0.1\r\n" +
		"X-Forwarded-Uri: /admin\r\n" +
		"X-Forwarded-Tls-Client-Cert: MIIB\r\n" +
		// Underscores, because Go keeps the name as it arrived and plenty of
		// things behind a proxy read this one as X-Forwarded-For.
		"X_Forwarded_For: 10.0.0.2\r\n" +
		"\r\n")

	select {
	case head := <-got:
		for _, claim := range []string{
			"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
			"X-Real-Ip", "Forwarded", "X-Client-Ip", "X-Forwarded-Uri",
			"X-Forwarded-Tls-Client-Cert", "X_Forwarded_For",
		} {
			if strings.Contains(head, claim+":") {
				t.Errorf("%s reached the upstream:\n%s", claim, head)
			}
		}
		if !strings.Contains(head, "Authorization: Bearer injected") {
			t.Fatalf("the credential did not reach the upstream:\n%s", head)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the request never reached the upstream")
	}
}

// An operator who wants one of them can still set it, because a configured
// header is the controlplane speaking rather than the sandbox.
func TestAConfiguredForwardedHeaderIsStillSent(t *testing.T) {
	upstream, got := requestRecorder(t)
	_, send := injectingProxy(t, upstream,
		vtunnel.WithHeader("X-Forwarded-For", "203.0.113.7"))

	send("GET /x HTTP/1.1\r\nHost: api.corp\r\nX-Forwarded-For: 10.0.0.1\r\n\r\n")

	select {
	case head := <-got:
		if !strings.Contains(head, "X-Forwarded-For: 203.0.113.7") {
			t.Fatalf("the configured value did not reach the upstream:\n%s", head)
		}
		if strings.Contains(head, "10.0.0.1") {
			t.Fatalf("the sandbox's own value survived:\n%s", head)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the request never reached the upstream")
	}
}
