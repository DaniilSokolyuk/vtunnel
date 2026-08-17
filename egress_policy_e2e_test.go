package vtunnel_test

// The egress policy across a real tunnel: declared on the controlplane, applied
// in the sandbox, and still applied after the link has flapped.
//
// egress_policy_test.go proves the sandbox enforces what it was given. What is
// left to prove is that it is given it at all — which is where this feature is
// most easily broken, because the configuration that needs it most declares no
// forwarded domain, and every mechanism the tunnel already had for telling the
// sandbox anything was keyed on there being one.

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

// connectVia asks an egress proxy for a tunnel and reports the status.
func connectVia(t *testing.T, egressAddr, target string) int {
	t.Helper()

	conn, err := net.DialTimeout("tcp", egressAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial the egress proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// waitForVerdict polls until the egress proxy answers as expected, or gives up.
// The policy arrives over the tunnel, so there is no moment the caller can
// synchronise on other than the answer changing.
func waitForVerdict(t *testing.T, egressAddr, target string, want int) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	var got int
	for time.Now().Before(deadline) {
		if got = connectVia(t, egressAddr, target); got == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("CONNECT %s = %d, want %d within the deadline", target, got, want)
}

// The configuration this feature exists for declares no forwarded domain at
// all: refuse everything, permit a couple of names. Every path the tunnel had
// for telling the sandbox anything was keyed on there being a domain to
// forward, so this is the case that would silently never arrive.
func TestEgressPolicyReachesASandboxWithNoForwardedDomains(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer backend.Close()

	ts, server := startTunnelServer(t)
	defer ts.Close()

	egressAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := server.StartProxy(egressAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	client := vtunnel.NewClient(wsURL(ts))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	// Open until told otherwise.
	if got := connectVia(t, egressAddr, backend.Listener.Addr().String()); got != http.StatusOK {
		t.Fatalf("CONNECT before the policy = %d, want 200", got)
	}

	if err := client.SetEgressPolicy(vtunnel.Policy{Default: vtunnel.ActionDeny}); err != nil {
		t.Fatalf("SetEgressPolicy: %v", err)
	}
	waitForVerdict(t, egressAddr, backend.Listener.Addr().String(), http.StatusForbidden)
}

// A policy declared before the client connects is sent once it does, the same
// way a route is. Otherwise the order of two calls on the controlplane would
// decide whether the sandbox is contained.
func TestEgressPolicyDeclaredBeforeConnectingIsStillDelivered(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer backend.Close()

	ts, server := startTunnelServer(t)
	defer ts.Close()

	egressAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := server.StartProxy(egressAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	client := vtunnel.NewClient(wsURL(ts))
	defer client.Close()

	if err := client.SetEgressPolicy(vtunnel.Policy{Default: vtunnel.ActionDeny}); err != nil {
		t.Fatalf("SetEgressPolicy before Connect: %v", err)
	}
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	waitForVerdict(t, egressAddr, backend.Listener.Addr().String(), http.StatusForbidden)
}

// A sandbox that comes back knows nothing until it is told again, and a fresh
// sandbox process never knew anything at all. Both look the same from here, and
// both must end up with the policy this client holds.
func TestEgressPolicySurvivesAReconnect(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer backend.Close()

	ts, server := startTunnelServer(t)
	defer ts.Close()

	egressAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := server.StartProxy(egressAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	client := vtunnel.NewClient(wsURL(ts),
		vtunnel.WithReconnectBackoff(20*time.Millisecond, 50*time.Millisecond))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	target := backend.Listener.Addr().String()
	if err := client.SetEgressPolicy(vtunnel.Policy{Default: vtunnel.ActionDeny}); err != nil {
		t.Fatalf("SetEgressPolicy: %v", err)
	}
	waitForVerdict(t, egressAddr, target, http.StatusForbidden)

	// Drop the tunnel underneath it. Nothing clears the sandbox's policy, so what
	// is being watched for here is the replay undoing it — the reconnect path
	// re-sends everything this client knows, and a policy sent as part of that
	// must arrive as the same policy rather than as an empty one.
	ts.CloseClientConnections()

	until := time.Now().Add(2 * time.Second)
	for time.Now().Before(until) {
		if got := connectVia(t, egressAddr, target); got != http.StatusForbidden {
			t.Fatalf("CONNECT across the reconnect = %d, want 403 throughout", got)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Withdrawing is spelled as a policy that allows everything, not as an absence.
// An absence is indistinguishable from never having sent one, and the sandbox
// would keep enforcing whatever it last heard.
func TestEgressPolicyIsWithdrawnByAllowingEverything(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer backend.Close()

	ts, server := startTunnelServer(t)
	defer ts.Close()

	egressAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := server.StartProxy(egressAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	client := vtunnel.NewClient(wsURL(ts))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	target := backend.Listener.Addr().String()
	if err := client.SetEgressPolicy(vtunnel.Policy{Default: vtunnel.ActionDeny}); err != nil {
		t.Fatalf("SetEgressPolicy: %v", err)
	}
	waitForVerdict(t, egressAddr, target, http.StatusForbidden)

	if err := client.SetEgressPolicy(vtunnel.Policy{Default: vtunnel.ActionAllow}); err != nil {
		t.Fatalf("SetEgressPolicy allow: %v", err)
	}
	waitForVerdict(t, egressAddr, target, http.StatusOK)
}

// A rule that cannot be read is the caller's error, returned to the caller,
// before anything is sent. Reporting it from the sandbox's log would be
// reporting it to nobody.
func TestSetEgressPolicyRejectsUnreadableRulesLocally(t *testing.T) {
	client := vtunnel.NewClient("ws://127.0.0.1:1/")
	defer client.Close()

	if err := client.SetEgressPolicy(vtunnel.Policy{Allow: []string{"api corp"}}); err == nil {
		t.Fatal("SetEgressPolicy accepted an unreadable rule")
	}
}

// The sandbox can be closed before any controlplane exists, which is the only
// way to close the window between a sandbox becoming usable and its policy
// arriving.
func TestServerEgressPolicyAppliesBeforeAnyClientConnects(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer backend.Close()

	server := vtunnel.NewServer(vtunnel.WithServerEgressPolicy(vtunnel.Policy{Default: vtunnel.ActionDeny}))
	defer server.Close()

	egressAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := server.StartProxy(egressAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}

	// No client has ever connected, and there is no tunnel at all.
	if got := connectVia(t, egressAddr, backend.Listener.Addr().String()); got != http.StatusForbidden {
		t.Fatalf("CONNECT = %d, want 403 before any controlplane exists", got)
	}
}

// And what the controlplane sends replaces it, rather than being merged with it
// or refused because something was already there.
func TestClientPolicyReplacesTheServerOne(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer backend.Close()

	server := vtunnel.NewServer(vtunnel.WithServerEgressPolicy(vtunnel.Policy{Default: vtunnel.ActionDeny}))
	upgrader := vtunnel.NewUpgrader()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		server.HandleWebSocket(conn)
	}))
	defer ts.Close()
	defer server.Close()

	egressAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := server.StartProxy(egressAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}

	target := backend.Listener.Addr().String()
	if got := connectVia(t, egressAddr, target); got != http.StatusForbidden {
		t.Fatalf("CONNECT before the client = %d, want 403", got)
	}

	client := vtunnel.NewClient(wsURL(ts))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	if err := client.SetEgressPolicy(vtunnel.Policy{Allow: []string{"127.0.0.0/8"}}); err != nil {
		t.Fatalf("SetEgressPolicy: %v", err)
	}
	waitForVerdict(t, egressAddr, target, http.StatusOK)
}
