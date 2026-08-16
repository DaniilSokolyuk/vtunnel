package vtunnel_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/vivid-money/vtunnel"
)

// A domain can be served from this process: the proxy terminates TLS and calls
// the handler with the decrypted request. That is what lets per-service
// handlers live in the proxy itself instead of behind a second one.
func TestHandleServesDomainInProcess(t *testing.T) {
	ca := generateTestCA(t)
	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxy.Close()

	proxy.Handle("gitlab.corp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The handler sees a normal decrypted request, host and all.
		fmt.Fprintf(w, "handled %s%s auth=%s", r.Host, r.URL.Path, r.Header.Get("Authorization"))
	}), vtunnel.WithHeader("Authorization", "Bearer from-config"))

	client := proxyClient(t, proxy.Addr().String(), ca)
	got := readAll(t, client, "https://gitlab.corp/api/v4/projects")

	want := "handled gitlab.corp/api/v4/projects auth=Bearer from-config"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Middleware wraps every terminated request, whichever way it is served, so
// audit and identity are declared once rather than per route.
func TestUseWrapsHandlerAndForwardedRoutes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "upstream")
	}))
	defer upstream.Close()

	ca := generateTestCA(t)
	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))

	var mu sync.Mutex
	var seen []string
	proxy.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seen = append(seen, r.Host)
			mu.Unlock()
			w.Header().Set("X-Middleware", "ran")
			next.ServeHTTP(w, r)
		})
	})

	if err := proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxy.Close()

	proxy.Handle("inproc.corp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "inproc")
	}))
	if err := proxy.ForwardTo("fwd.corp", upstream.Listener.Addr().String()); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}

	client := proxyClient(t, proxy.Addr().String(), ca)
	for _, host := range []string{"inproc.corp", "fwd.corp"} {
		resp, err := client.Get("https://" + host + "/")
		if err != nil {
			t.Fatalf("GET %s: %v", host, err)
		}
		resp.Body.Close()
		if resp.Header.Get("X-Middleware") != "ran" {
			t.Fatalf("%s: middleware did not run", host)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || seen[0] != "inproc.corp" || seen[1] != "fwd.corp" {
		t.Fatalf("middleware saw %v, want both routes", seen)
	}
}

// HandleUnmapped turns the proxy from "dial anything" into "serve only what is
// routed" — the posture a controlplane proxy wants, so a compromised sandbox
// cannot use it as an open relay.
func TestHandleUnmappedRefusesUnknownDomains(t *testing.T) {
	ca := generateTestCA(t)
	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	proxy.HandleUnmapped(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unknown domain", http.StatusForbidden)
	}))
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxy.Close()

	proxy.Handle("known.corp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "known")
	}))

	client := proxyClient(t, proxy.Addr().String(), ca)

	if got := readAll(t, client, "https://known.corp/"); got != "known" {
		t.Fatalf("routed domain = %q", got)
	}

	// CONNECT itself must be refused: opening the tunnel first and rejecting
	// later would still have dialled the host.
	_, err := client.Get("https://unknown.corp/")
	if err == nil {
		t.Fatal("unrouted domain was served")
	}
	if !strings.Contains(err.Error(), "403") && !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("unrouted domain failed with %v, want a refusal", err)
	}
}

// Plain HTTP goes through the same routing, so a handler route serves :80 too.
func TestHandleServesPlainHTTP(t *testing.T) {
	proxy := vtunnel.NewMITMProxy()
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxy.Close()

	proxy.Handle("plain.corp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "plain %s", r.URL.Path)
	}))

	client := &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(mustParseURL(t, "http://"+proxy.Addr().String())),
		DisableKeepAlives: true,
	}}
	if got := readAll(t, client, "http://plain.corp/hello"); got != "plain /hello" {
		t.Fatalf("got %q", got)
	}
}
