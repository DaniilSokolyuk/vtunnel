package vtunnel_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The Host of a request inside an intercepted tunnel, and what it is compared
// against. The comparison is what stops a sandbox opening a CONNECT to a domain
// it may reach and then aiming the injected credential at another virtual host
// on the same upstream; an absent Host is not a claim about a different host,
// and had nothing to compare.

// HTTP/1.0 has no Host header, and net/http passes such a request to the
// handler as it stands. Comparing that empty Host against the CONNECT authority
// made every HTTP/1.0 request inside an intercepted tunnel a 421 — the check is
// right and necessary, it just had nothing to compare.
func TestHTTP10WithoutHostIsServedInsideMITM(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "auth=%s host=%s", r.Header.Get("Authorization"), r.Host)
	}))
	defer backend.Close()

	addr, ca := gapProxy(t, backend.Listener.Addr().String())
	tc := connectThenTLS(t, addr, "probe.test:443", "probe.test", "", ca)

	resp := requestOver(t, tc, "GET / HTTP/1.0\r\n\r\n")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %s, want 200: an HTTP/1.0 request has no Host to match, and "+
			"the authority it arrived on is the answer", resp.Status)
	}
	if !strings.Contains(string(body), "auth=Bearer injected") {
		t.Fatalf("body = %q, want the injected credential", body)
	}
	if !strings.Contains(string(body), "host=probe.test") {
		t.Fatalf("body = %q, want the CONNECT authority filled in as the Host", body)
	}
}

// The guard it sits next to still holds: a request aimed at another virtual
// host is refused, because that is how a sandbox would point an injected
// credential somewhere it was never meant to go.
func TestMismatchedHostInsideMITMIsStillRefused(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "reached")
	}))
	defer backend.Close()

	addr, ca := gapProxy(t, backend.Listener.Addr().String())
	tc := connectThenTLS(t, addr, "probe.test:443", "probe.test", "", ca)

	resp := requestOver(t, tc, "GET / HTTP/1.1\r\nHost: other.test\r\n\r\n")
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status = %s, want 421", resp.Status)
	}
}
