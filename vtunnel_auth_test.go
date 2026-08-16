package vtunnel_test

// One secret, both ends: what it accepts and what it refuses.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/vivid-money/vtunnel"
)

func startAuthServer(t *testing.T, secret string) *httptest.Server {
	t.Helper()
	server := vtunnel.NewServer(vtunnel.WithServerSecret(secret))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		server.HandleWebSocket(conn)
	}))
	return ts
}

// secretA and secretB are two unrelated tunnel secrets. Nothing about their
// shape matters — a secret is any string hard enough to guess, and these are
// what an orchestrator handing one to each sandbox would produce.
const (
	secretA = "8Kq2vX7mR4nP1tY5uB9cD3fJ6wZ0aE"
	secretB = "3f2a9c41-77b1-4de6-9f0a-1c5e8b2d4a63"
)

// 1. Whatever the operator decided a secret is, it is one: a random blob, a
// UUID from an orchestrator, an opaque token out of a secret manager. Demanding
// a format would prove nothing about the only property that counts.
func TestSecretAcceptsAnyString(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"random blob", secretA},
		{"uuid", secretB},
		{"opaque token from a secret manager", "AQICAHhw3l2Kq9vZ0pR7sT1uY4nB6mC8dE0fG2hJ"},
		{"short, warned about but accepted", "hunter2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := vtunnel.NewClient("ws://unused/", vtunnel.WithSecret(tc.value))
			defer c.Close()
		})
	}
}

// 3. The same secret on both ends connects and tunnels.
func TestAuthValidSecret(t *testing.T) {
	secret := secretA

	ts := startAuthServer(t, secret)
	defer ts.Close()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("authenticated"))
	}))
	defer backend.Close()

	client := vtunnel.NewClient(wsURL(ts), vtunnel.WithSecret(secret))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect with the matching secret: %v", err)
	}
	defer client.Close()

	port := freePort(t)
	if err := client.Listen(port, backend.Listener.Addr().String()); err != nil {
		t.Fatal(err)
	}

	waitForHTTP(t, port, "authenticated", 3*time.Second)
}

// 4. A different secret is refused — and refused at the host key, before the
// client ever offers its own credentials to a server it should not trust.
func TestAuthWrongSecret(t *testing.T) {
	ts := startAuthServer(t, secretA)
	defer ts.Close()

	client := vtunnel.NewClient(wsURL(ts), vtunnel.WithSecret(secretB))
	err := client.Connect()
	if err == nil {
		client.Close()
		t.Fatal("Connect succeeded with a secret the server does not share")
	}
	if !strings.Contains(err.Error(), "host key") {
		t.Fatalf("expected the host key check to fire first, got: %v", err)
	}
	t.Logf("correctly rejected: %v", err)
}

// 5. Server with a secret, client without — rejected.
func TestAuthNoSecretOnClient(t *testing.T) {
	ts := startAuthServer(t, secretA)
	defer ts.Close()

	client := vtunnel.NewClient(wsURL(ts))
	err := client.Connect()
	if err == nil {
		client.Close()
		t.Fatal("expected Connect to fail without a secret, but it succeeded")
	}
	t.Logf("correctly rejected: %v", err)
}

// 6. No secret on either side — unauthenticated, and still working. The warning
// both sides log at startup is the only thing standing between this mode and
// production.
func TestAuthNoSecretOnServer(t *testing.T) {
	ts, _ := startTunnelServer(t)
	defer ts.Close()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("noauth"))
	}))
	defer backend.Close()

	client := vtunnel.NewClient(wsURL(ts))
	if err := client.Connect(); err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	port := freePort(t)
	client.Listen(port, backend.Listener.Addr().String())
	waitForHTTP(t, port, "noauth", 3*time.Second)
}

// 7. Reconnect re-authenticates from the same secret.
func TestAuthReconnectWithSecret(t *testing.T) {
	secret := secretA

	server := vtunnel.NewServer(vtunnel.WithServerSecret(secret))
	connCh := make(chan *websocket.Conn, 20)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		connCh <- conn
		server.HandleWebSocket(conn)
	}))
	defer ts.Close()

	client := vtunnel.NewClient(wsURL(ts),
		vtunnel.WithKeepAlive(200*time.Millisecond),
		vtunnel.WithReconnectBackoff(50*time.Millisecond, 200*time.Millisecond),
		vtunnel.WithSecret(secret),
	)
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	// Wait for initial WS connection
	deadline := time.After(5 * time.Second)
	for len(connCh) == 0 {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for initial WS connection")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("auth-reconnect"))
	}))
	defer backend.Close()

	port := freePort(t)
	if err := client.Listen(port, backend.Listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	waitForHTTP(t, port, "auth-reconnect", 3*time.Second)

	// Kill current WS connection
	select {
	case conn := <-connCh:
		conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("no WS connection to kill")
	}

	// Wait for reconnect
	deadline = time.After(5 * time.Second)
	for len(connCh) == 0 {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for WS reconnect")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Tunnel should still work after reconnect with auth
	waitForHTTP(t, port, "auth-reconnect", 5*time.Second)
	t.Log("Auth reconnect works")
}
