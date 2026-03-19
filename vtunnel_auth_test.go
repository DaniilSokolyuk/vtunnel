package vtunnel_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

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
		client.Close()
		t.Fatal("expected Connect to fail with wrong key, but it succeeded")
	}
	t.Logf("Connect correctly rejected: %v", err)
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
		client.Close()
		t.Fatal("expected Connect to fail without key, but it succeeded")
	}
	t.Logf("Connect correctly rejected: %v", err)
}

// 4b. Attacker knows the public key (visible on server/Docker), derives
// the correct server_pub_hash, but authenticates with their own private key.
// Must fail on auth (unauthorized key), NOT MITM detection.
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

	// Derive the correct server_pub_hash from the known public key
	// (same as deriveServerIdentity does internally: SHA256 of raw pubkey bytes)
	pubBytes, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(pub, "vt-pub-"))
	if err != nil {
		t.Fatal(err)
	}
	expectedHash := sha256.Sum256(pubBytes)

	// Connect via WebSocket and perform custom handshake manually
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	wsConn, _, err := dialer.Dial(wsURL(ts), nil)
	if err != nil {
		t.Fatalf("WS dial: %v", err)
	}
	defer wsConn.Close()
	conn := vtunnel.NewWSConn(wsConn)

	// Read challenge from server
	var challenge struct {
		Challenge     string `json:"challenge"`
		ServerPubHash string `json:"server_pub_hash"`
	}
	if err := vtunnel.ReadMsg(conn, &challenge); err != nil {
		t.Fatalf("read challenge: %v", err)
	}

	// Verify server_pub_hash matches what we expect from the known public key
	serverHash, err := base64.StdEncoding.DecodeString(challenge.ServerPubHash)
	if err != nil {
		t.Fatalf("decode server_pub_hash: %v", err)
	}
	if !bytes.Equal(serverHash, expectedHash[:]) {
		t.Fatal("server_pub_hash does not match expected — test setup error")
	}

	// Sign the challenge with the attacker's key (wrong key)
	challengeBytes, err := base64.StdEncoding.DecodeString(challenge.Challenge)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	sig := ed25519.Sign(attackerPriv, challengeBytes)
	attackerPub := attackerPriv.Public().(ed25519.PublicKey)

	// Send response with attacker's public key and signature
	resp := struct {
		Signature string `json:"signature"`
		ClientPub string `json:"client_pub"`
	}{
		Signature: base64.StdEncoding.EncodeToString(sig),
		ClientPub: base64.StdEncoding.EncodeToString(attackerPub),
	}
	if err := vtunnel.WriteMsg(conn, resp); err != nil {
		t.Fatalf("send response: %v", err)
	}

	// Read result — should be rejected
	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error,omitempty"`
	}
	if err := vtunnel.ReadMsg(conn, &result); err != nil {
		t.Fatalf("read result: %v", err)
	}
	if result.OK {
		t.Fatal("expected auth failure, but handshake succeeded")
	}
	if !strings.Contains(result.Error, "unauthorized key") {
		t.Fatalf("expected 'unauthorized key', got: %q", result.Error)
	}
	t.Logf("Correctly rejected at auth (not MITM): %v", result.Error)
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
