package vtunnel_test

// Clearing the last route.
//
// Removing a forward is not a controlplane-only affair: while the sandbox
// router still holds the domain, every request for it is chained into a
// controlplane that no longer knows it, and comes back 403 — forever, across
// reconnects, with the route the operator already deleted. Direct egress, which
// is what "not forwarded" means everywhere else, never comes back.
//
// ExampleMITMProxy_Remove promises exactly this ("api.corp now egresses from
// the sandbox directly"), and doc.go promises the mechanism ("each call
// re-sends the full domain list, which the router applies wholesale").

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

func TestRemovingTheLastRouteReachesTheSandbox(t *testing.T) {
	chained := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "chained")
	}))
	defer chained.Close()

	// Stands in for the real host: reachable directly from the sandbox, and the
	// evidence that the route is gone is that requests land here again.
	decoy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "decoy")
	}))
	decoy.StartTLS()
	defer decoy.Close()

	ts, server := startTunnelServer(t)
	defer ts.Close()

	routerAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := server.StartProxy(routerAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	client := vtunnel.NewClient(wsURL(ts), vtunnel.WithMitm(generateTestCA(t)))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	httpClient := routerClient(t, routerAddr)
	authority := decoy.Listener.Addr().String()
	decoyURL := "https://" + authority + "/"

	// One route, and only one: this is the case the guard in syncRoutes swallows.
	if err := client.Proxy().ForwardTo(authority, chained.Listener.Addr().String()); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if got := getBody(t, httpClient, decoyURL); got != "chained" {
		t.Fatalf("while forwarded = %q, want chained", got)
	}

	client.Proxy().Remove(authority)
	time.Sleep(150 * time.Millisecond)
	if got := getBody(t, httpClient, decoyURL); got != "decoy" {
		t.Fatalf("after removing the only route = %q, want decoy: the sandbox still holds "+
			"the route and chains into a controlplane that no longer knows the domain", got)
	}
}

// The same clearing must survive a reconnect: the client replays what it has,
// and what it has is nothing.
func TestClearedRoutesStayClearedAfterReconnect(t *testing.T) {
	chained := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "chained")
	}))
	defer chained.Close()

	decoy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "decoy")
	}))
	decoy.StartTLS()
	defer decoy.Close()

	ts, server := startTunnelServer(t)
	defer ts.Close()

	routerAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := server.StartProxy(routerAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	client := vtunnel.NewClient(wsURL(ts), vtunnel.WithMitm(generateTestCA(t)),
		vtunnel.WithReconnectBackoff(50*time.Millisecond, 200*time.Millisecond))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	httpClient := routerClient(t, routerAddr)
	authority := decoy.Listener.Addr().String()
	decoyURL := "https://" + authority + "/"

	if err := client.Proxy().ForwardTo(authority, chained.Listener.Addr().String()); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	client.Proxy().Remove(authority)
	time.Sleep(150 * time.Millisecond)

	// Drop the transport under the client and let it come back.
	ts.CloseClientConnections()
	deadline := time.Now().Add(5 * time.Second)
	for {
		// Errors are expected while the tunnel is down; a "chained" body is not,
		// and neither is running out of time.
		resp, err := httpClient.Get(decoyURL)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) == "decoy" {
				break
			}
			if string(body) == "chained" {
				t.Fatal("after a reconnect the removed route came back and the domain is chained again")
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("direct egress never came back after the reconnect (last error: %v)", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
