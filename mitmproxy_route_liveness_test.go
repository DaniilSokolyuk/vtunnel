package vtunnel_test

// A route is a live piece of configuration, not a snapshot taken when the
// connection opened. Rotating a credential, repointing a domain at a new
// backend and withdrawing one altogether are all things the controlplane does
// while the sandbox is running — and how long a connection stays open is the
// sandbox's decision, so a route bound to the connection is a route the
// sandbox can hold open indefinitely.

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vivid-money/vtunnel"
)

// namedUpstream answers with its own name and the credential it was handed, so
// one request tells you both where it went and what it carried.
func namedUpstream(t *testing.T, name string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s auth=%q", name, r.Header.Get("Authorization"))
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func requestOnTunnel(t *testing.T, tc io.ReadWriter, path string) (*http.Response, string) {
	t.Helper()
	fmt.Fprintf(tc, "GET %s HTTP/1.1\r\nHost: api.corp\r\n\r\n", path)
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatalf("read response for %s: %v", path, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

// Rotating the credential must reach the connection that is already open. A
// gRPC channel or a browser's origin pool holds one intercepted connection for
// hours, so a rotation that only applies to the next CONNECT is a rotation that
// never happens: the sandbox keeps presenting the retired token.
func TestCredentialRotationReachesALiveConnection(t *testing.T) {
	upstream := namedUpstream(t, "A")

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("api.corp", upstream, vtunnel.WithHeader("Authorization", "v1")); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	tc := connectThenTLS(t, p.Addr().String(), "api.corp:443", "api.corp", "", ca)
	if _, body := requestOnTunnel(t, tc, "/one"); body != `A auth="v1"` {
		t.Fatalf("first request: %s", body)
	}

	if err := p.ForwardTo("api.corp", upstream, vtunnel.WithHeader("Authorization", "v2")); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, body := requestOnTunnel(t, tc, "/two"); body != `A auth="v2"` {
		t.Fatalf("after rotating the credential the same connection sent %s, want the new one: "+
			"the credential was captured when the tunnel opened", body)
	}
}

// Repointing a domain at another backend is the same shape, and it decides
// where live traffic goes during a failover or a migration.
func TestRepointingReachesALiveConnection(t *testing.T) {
	first, second := namedUpstream(t, "A"), namedUpstream(t, "B")

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("api.corp", first); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	tc := connectThenTLS(t, p.Addr().String(), "api.corp:443", "api.corp", "", ca)
	if _, body := requestOnTunnel(t, tc, "/one"); body != `A auth=""` {
		t.Fatalf("first request: %s", body)
	}

	if err := p.ForwardTo("api.corp", second); err != nil {
		t.Fatalf("repoint: %v", err)
	}
	if _, body := requestOnTunnel(t, tc, "/two"); body != `B auth=""` {
		t.Fatalf("after repointing, the same connection still reached %s", body)
	}
}

// Withdrawing a route is a security control, and it was not one: the domain
// stayed served, with the retired credential attached, for as long as the
// sandbox kept the connection open. A fresh connection was refused, which made
// it look like the withdrawal had taken effect.
func TestRemovedRouteStopsBeingServedOnALiveConnection(t *testing.T) {
	upstream := namedUpstream(t, "A")

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	p.HandleUnmapped(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "vtunnel: domain not allowed", http.StatusForbidden)
	}))
	if err := p.ForwardTo("api.corp", upstream, vtunnel.WithHeader("Authorization", "v1")); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	tc := connectThenTLS(t, p.Addr().String(), "api.corp:443", "api.corp", "", ca)
	if _, body := requestOnTunnel(t, tc, "/one"); body != `A auth="v1"` {
		t.Fatalf("first request: %s", body)
	}

	p.Remove("api.corp")
	resp, body := requestOnTunnel(t, tc, "/two")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("after Remove the same connection answered %s %q, want 403: a withdrawn "+
			"route kept being served, credential and all", resp.Status, body)
	}
}

// Middleware registered after the connection opened applies to it too — Use is
// documented as configuration, and configuration is live.
func TestMiddlewareAddedLaterAppliesToALiveConnection(t *testing.T) {
	upstream := namedUpstream(t, "A")

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
	requestOnTunnel(t, tc, "/one")

	p.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Late", "yes")
			next.ServeHTTP(w, r)
		})
	})
	resp, _ := requestOnTunnel(t, tc, "/two")
	if resp.Header.Get("X-Late") != "yes" {
		t.Fatal("middleware added after the connection opened did not apply to it")
	}
}

// Replacing a handler route replaces what the live connection is served by.
func TestHandlerReplacementReachesALiveConnection(t *testing.T) {
	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	p.Handle("api.corp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "first")
	}))
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	tc := connectThenTLS(t, p.Addr().String(), "api.corp:443", "api.corp", "", ca)
	if _, body := requestOnTunnel(t, tc, "/one"); body != "first" {
		t.Fatalf("first request: %q", body)
	}

	p.Handle("api.corp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "second")
	}))
	if _, body := requestOnTunnel(t, tc, "/two"); body != "second" {
		t.Fatalf("after replacing the handler the same connection answered %q", body)
	}
}
