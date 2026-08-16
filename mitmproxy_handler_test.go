package vtunnel_test

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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
// The CA is not used on this path — nothing is decrypted — but a handler route
// is refused without one, because the same declaration also covers :443.
func TestHandleServesPlainHTTP(t *testing.T) {
	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(generateTestCA(t)))
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxy.Close()

	if err := proxy.Handle("plain.corp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "plain %s", r.URL.Path)
	})); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	client := &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(mustParseURL(t, "http://"+proxy.Addr().String())),
		DisableKeepAlives: true,
	}}
	if got := readAll(t, client, "http://plain.corp/hello"); got != "plain /hello" {
		t.Fatalf("got %q", got)
	}
}

// Header injection happens after TLS is terminated. On a proxy with no CA there
// is nothing to terminate, so a route configured with headers would answer
// requests perfectly normally and simply never add the credential — a failure
// with no error and no missing response to notice. The CLI has always rejected
// `-H` without `-mitm-ca`; the library now rejects the same thing.
func TestRoutesThatNeedDecryptionAreRefusedWithoutCA(t *testing.T) {
	proxy := vtunnel.NewMITMProxy()

	t.Run("headers", func(t *testing.T) {
		err := proxy.ForwardTo("api.corp", "localhost:8081",
			vtunnel.WithHeader("Authorization", "Bearer secret"))
		if err == nil {
			t.Fatal("header injection was accepted on a proxy that cannot decrypt")
		}
		if !strings.Contains(err.Error(), "MITM CA") {
			t.Fatalf("err = %v, want it to name the missing CA", err)
		}
		if got := proxy.Routes(); len(got) != 0 {
			t.Fatalf("the rejected route was registered anyway: %v", got)
		}
	})

	t.Run("in-process handler", func(t *testing.T) {
		err := proxy.Handle("mock.corp", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		if err == nil {
			t.Fatal("a handler route was accepted on a proxy that cannot decrypt")
		}
		if !strings.Contains(err.Error(), "MITM CA") {
			t.Fatalf("err = %v, want it to name the missing CA", err)
		}
		if got := proxy.Routes(); len(got) != 0 {
			t.Fatalf("the rejected route was registered anyway: %v", got)
		}
	})
}

// What a CA-less proxy is still good for: routing domains to other addresses
// and piping their TLS through untouched. Refusing the cases above must not
// take this with it.
func TestCALessProxyStillRoutes(t *testing.T) {
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "reached")
	}))
	backend.StartTLS()
	defer backend.Close()

	proxy := vtunnel.NewMITMProxy()
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxy.Close()

	if err := proxy.ForwardTo("plain.corp:443", backend.Listener.Addr().String()); err != nil {
		t.Fatalf("ForwardTo without headers must still work: %v", err)
	}
	proxy.Forward("passthrough.corp")

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(mustParseURL(t, "http://"+proxy.Addr().String())),
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}
	if got := readAll(t, client, "https://plain.corp/"); got != "reached" {
		t.Fatalf("got %q, want the backend's response", got)
	}
}
