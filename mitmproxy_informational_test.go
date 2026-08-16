package vtunnel_test

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vivid-money/vtunnel"
)

// Responses that arrive before the response: 103 Early Hints telling a client
// what to fetch while the upstream is still working, and the 100 Continue that
// answers an expectation about a request body.

// An informational response is a real answer that arrives before the real
// answer: 103 Early Hints tells a browser what to start fetching while the
// upstream is still thinking. RoundTrip does not surface them, so they were
// dropped — the client got the 200 and none of the hints.
func TestInformationalResponsesReachTheClient(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</style.css>; rel=preload; as=style")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("Link")
		fmt.Fprint(w, "done")
	}))
	defer backend.Close()

	addr, ca := gapProxy(t, backend.Listener.Addr().String())
	tc := connectThenTLS(t, addr, "probe.test:443", "probe.test", "", ca)

	if _, err := io.WriteString(tc, "GET / HTTP/1.1\r\nHost: probe.test\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}

	br := bufio.NewReader(tc)
	early, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read first response: %v", err)
	}
	if early.StatusCode != http.StatusEarlyHints {
		t.Fatalf("first response = %s, want 103 Early Hints", early.Status)
	}
	if got := early.Header.Get("Link"); got != "</style.css>; rel=preload; as=style" {
		t.Fatalf("103 Link = %q", got)
	}

	final, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read final response: %v", err)
	}
	body, _ := io.ReadAll(final.Body)
	final.Body.Close()
	if final.StatusCode != http.StatusOK || string(body) != "done" {
		t.Fatalf("final response = %s %q", final.Status, body)
	}
	// The hint's headers belong to the hint, not to the answer.
	if got := final.Header.Get("Link"); got != "" {
		t.Fatalf("the 200 carried the 103's Link header (%q)", got)
	}
}

// Expect: 100-continue is a conversation between the client and whoever reads
// its body, and net/http holds up that end itself — it answers 100 the moment
// the handler starts reading. Forwarding the upstream's 100 as well left the
// client with two of them for one request.
func TestExpectContinueIsAnsweredExactlyOnce(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "got %q", body)
	}))
	defer backend.Close()

	addr, ca := gapProxy(t, backend.Listener.Addr().String())
	tc := connectThenTLS(t, addr, "probe.test:443", "probe.test", "", ca)

	fmt.Fprint(tc, "POST /x HTTP/1.1\r\nHost: probe.test\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n")

	br := bufio.NewReader(tc)
	interim, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read interim: %v", err)
	}
	if interim.StatusCode != http.StatusContinue {
		t.Fatalf("interim = %s, want 100 Continue", interim.Status)
	}

	fmt.Fprint(tc, "HELLO")

	final, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	if final.StatusCode == http.StatusContinue {
		t.Fatal("the client was told 100 Continue twice: net/http answers the expectation " +
			"itself, and the upstream's answer to the same expectation was forwarded on top")
	}
	body, _ := io.ReadAll(final.Body)
	final.Body.Close()
	if final.StatusCode != http.StatusOK || string(body) != `got "HELLO"` {
		t.Fatalf("final = %s %q", final.Status, body)
	}
}

// An informational response is the hint's, and only the hint's. Clearing the
// header map after writing it took everything else with it, including whatever
// a Use middleware had already set for the real response: that header was on
// every answer until the day an upstream sent 103, and then silently on none.
func TestEarlyHintsLeaveMiddlewareHeadersAlone(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</style.css>; rel=preload; as=style")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("Link")
		fmt.Fprint(w, "done")
	}))
	defer backend.Close()

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	p.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Proxy-Stamp", "vtunnel")
			next.ServeHTTP(w, r)
		})
	})
	if err := p.ForwardTo("probe.test", backend.Listener.Addr().String()); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	tc := connectThenTLS(t, p.Addr().String(), "probe.test:443", "probe.test", "", ca)
	if _, err := io.WriteString(tc, "GET / HTTP/1.1\r\nHost: probe.test\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}

	br := bufio.NewReader(tc)
	early, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read 103: %v", err)
	}
	if early.StatusCode != http.StatusEarlyHints {
		t.Fatalf("first response = %s, want 103", early.Status)
	}

	final, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	io.ReadAll(final.Body)
	final.Body.Close()

	if got := final.Header.Get("X-Proxy-Stamp"); got != "vtunnel" {
		t.Fatalf("X-Proxy-Stamp = %q on the final response: the 103 wiped the whole header "+
			"map, not just the headers the hint contributed", got)
	}
	if got := final.Header.Get("Link"); got != "" {
		t.Fatalf("the 200 carried the 103's Link header (%q)", got)
	}
}

// Padding is what a client writes instead of payload. Dropping blank lines
// before knowing which of the two this is corrupted the other one: a tunnel
// about to be piped through untouched had the opening bytes of its payload
// eaten, and the target read a message two bytes shorter than the one sent.
