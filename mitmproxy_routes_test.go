package vtunnel

// How route bookkeeping behaves as routes come and go.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ForwardTo records the TLS-ness of a target in a map keyed by address, while
// Remove only deleted from the route map, which is keyed by domain. Reusing the
// same address for a cleartext backend afterwards then made the proxy open a
// TLS handshake against a plain HTTP server and answer every request with 502 —
// and the map grew over every cycle of ForwardTo and Remove.
func TestRemoveClearsTheTLSUpstreamMark(t *testing.T) {
	cleartext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "plain upstream")
	}))
	defer cleartext.Close()
	addr := cleartext.Listener.Addr().String()

	proxy, proxyAddr, ca := startCoverageProxy(t, nil)

	// The first route marks the address as needing proxy-side TLS...
	proxy.ForwardTo("tlsroute.test:443", "tls://"+addr, WithSNI("tlsroute.test"))
	proxy.Remove("tlsroute.test")

	// ...and the mark must not outlive it: the same address is cleartext now.
	proxy.ForwardTo("plainroute.test:443", addr)

	body := getBody(t, coverageClient(proxyAddr, ca, true), "https://plainroute.test/")
	if body != "plain upstream" {
		t.Fatalf("body = %q; the stale TLS mark made the proxy handshake with a cleartext server", body)
	}

	// The TLS-ness now travels with the route, so there is no separate map to
	// fall out of step in the first place.
	proxy.domainMu.RLock()
	stale := proxy.routes["plainroute.test:443"].tlsHost
	proxy.domainMu.RUnlock()
	if stale != "" {
		t.Fatalf("the cleartext route carries tlsHost %q", stale)
	}
}

// Replacing a route can orphan the mark just as removing it can: the same
// domain pointed at a tls:// target a moment ago and at a cleartext one now.
func TestReplacingARouteClearsTheTLSUpstreamMark(t *testing.T) {
	cleartext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "plain upstream")
	}))
	defer cleartext.Close()
	addr := cleartext.Listener.Addr().String()

	proxy, proxyAddr, ca := startCoverageProxy(t, nil)
	proxy.ForwardTo("swap.test:443", "tls://"+addr, WithSNI("swap.test"))
	proxy.ForwardTo("swap.test:443", addr) // same domain, cleartext now

	if body := getBody(t, coverageClient(proxyAddr, ca, true), "https://swap.test/"); body != "plain upstream" {
		t.Fatalf("body = %q; the replaced route kept its TLS mark", body)
	}
}
