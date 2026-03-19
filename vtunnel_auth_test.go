package vtunnel_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/http2"

	"github.com/DaniilSokolyuk/vtunnel"
)

func startAuthServer(t *testing.T, clientKey string) *httptest.Server {
	t.Helper()
	server := vtunnel.NewServer(vtunnel.WithClientKey(clientKey))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		server.HandleConn(conn)
	}))
	return ts
}

// 1. GenerateKeyPair returns valid keys with correct prefixes.
func TestAuthKeyPairGeneration(t *testing.T) {
	priv, pub, err := vtunnel.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(priv, "vt-priv-") {
		t.Errorf("private key should start with vt-priv-, got %q", priv)
	}
	if !strings.HasPrefix(pub, "vt-pub-") {
		t.Errorf("public key should start with vt-pub-, got %q", pub)
	}
	t.Logf("Private: %s", priv)
	t.Logf("Public:  %s", pub)

	// Two calls produce different keys
	priv2, pub2, err := vtunnel.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if priv == priv2 {
		t.Error("two GenerateKeyPair calls produced identical private keys")
	}
	if pub == pub2 {
		t.Error("two GenerateKeyPair calls produced identical public keys")
	}
}

// 2. Client with correct key connects and tunnel works.
func TestAuthValidKey(t *testing.T) {
	priv, pub, err := vtunnel.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ts := startAuthServer(t, pub)
	defer ts.Close()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("authenticated"))
	}))
	defer backend.Close()

	client := vtunnel.NewClient(wsURL(ts), vtunnel.WithKey(priv))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect with valid key: %v", err)
	}
	defer client.Close()

	port := freePort(t)
	if err := client.Listen(port, backend.Listener.Addr().String()); err != nil {
		t.Fatal(err)
	}

	waitForHTTP(t, port, "authenticated", 3*time.Second)
}

// 3. Client with wrong key gets rejected.
func TestAuthWrongKey(t *testing.T) {
	_, pub, err := vtunnel.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ts := startAuthServer(t, pub)
	defer ts.Close()

	wrongPriv, _, err := vtunnel.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	client := vtunnel.NewClient(wsURL(ts), vtunnel.WithKey(wrongPriv))
	err = client.Connect()
	if err == nil {
		// Connect succeeds (WS+h2 connect fine), but control requests fail.
		// Try to listen — should fail with auth error.
		port := freePort(t)
		err = client.Listen(port, "localhost:1234")
		client.Close()
		if err == nil {
			t.Fatal("expected Listen to fail with wrong key, but it succeeded")
		}
	}
	t.Logf("Correctly rejected: %v", err)
}

// 4. Server with key, client without key — rejected.
func TestAuthNoKeyOnClient(t *testing.T) {
	_, pub, err := vtunnel.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ts := startAuthServer(t, pub)
	defer ts.Close()

	client := vtunnel.NewClient(wsURL(ts))
	err = client.Connect()
	if err == nil {
		// Connect succeeds (WS+h2 connect fine), but control requests fail.
		port := freePort(t)
		err = client.Listen(port, "localhost:1234")
		client.Close()
		if err == nil {
			t.Fatal("expected Listen to fail without key, but it succeeded")
		}
	}
	t.Logf("Correctly rejected: %v", err)
}

// 4b. Attacker knows the public key, derives a valid-looking token but with
// their own private key. Must fail with "authentication failed".
func TestAuthWrongPrivateKeyKnownPublic(t *testing.T) {
	_, pub, err := vtunnel.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ts := startAuthServer(t, pub)
	defer ts.Close()

	// Attacker generates their own ed25519 keypair
	_, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Connect via WebSocket and create h2 client
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	wsConn, _, err := dialer.Dial(wsURL(ts), nil)
	if err != nil {
		t.Fatalf("WS dial: %v", err)
	}
	defer wsConn.Close()

	conn := vtunnel.NewWSConn(wsConn)
	h2t := &http2.Transport{}
	h2cc, err := h2t.NewClientConn(conn)
	if err != nil {
		t.Fatalf("h2 client conn: %v", err)
	}

	// Send a request with attacker's token
	token := vtunnel.GenerateAuthToken(attackerPriv)
	req, _ := http.NewRequest("POST", "http://vtunnel/listen", strings.NewReader(`{"port":9999}`))
	req.Header.Set("Authorization", token)

	resp, err := h2cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", resp.StatusCode)
	}
	t.Logf("Correctly rejected with status %d", resp.StatusCode)
}

// 5. No keys on either side — works as before.
func TestAuthNoKeyOnServer(t *testing.T) {
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

// 6. Reconnect with key — auth replays correctly.
func TestAuthReconnectWithKey(t *testing.T) {
	priv, pub, err := vtunnel.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	server := vtunnel.NewServer(vtunnel.WithClientKey(pub))
	connCh := make(chan *websocket.Conn, 20)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		connCh <- conn
		server.HandleConn(conn)
	}))
	defer ts.Close()

	client := vtunnel.NewClient(wsURL(ts),
		vtunnel.WithKeepAlive(200*time.Millisecond),
		vtunnel.WithReconnectBackoff(50*time.Millisecond, 200*time.Millisecond),
		vtunnel.WithKey(priv),
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
