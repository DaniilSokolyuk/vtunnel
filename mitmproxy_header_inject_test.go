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
