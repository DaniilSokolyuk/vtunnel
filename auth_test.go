package vtunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"testing"
	"time"
)

func generateTestKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestHandshakeMatchingKeys(t *testing.T) {
	pub, priv := generateTestKeyPair(t)
	serverConn, clientConn := net.Pipe()

	errs := make(chan error, 2)
	go func() { errs <- serverHandshake(serverConn, pub) }()
	go func() { errs <- clientHandshake(clientConn, priv) }()

	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("handshake error: %v", err)
		}
	}
}

func TestHandshakeWrongKey(t *testing.T) {
	pub, _ := generateTestKeyPair(t)
	_, attackerPriv := generateTestKeyPair(t)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	serverErr := make(chan error, 1)
	clientErr := make(chan error, 1)
	go func() { serverErr <- serverHandshake(serverConn, pub) }()
	go func() {
		err := clientHandshake(clientConn, attackerPriv)
		clientConn.Close() // unblock server's readMsg
		clientErr <- err
	}()

	// Client should fail with MITM detection
	err := <-clientErr
	if err == nil {
		t.Fatal("expected client to detect MITM with wrong key")
	}
	if !strings.Contains(err.Error(), "server identity mismatch") {
		t.Fatalf("expected MITM detection error, got: %v", err)
	}

	// Server will fail due to pipe close
	<-serverErr
}

func TestHandshakeMITMDetection(t *testing.T) {
	// Server uses one public key, client has a different private key.
	// The client should detect the server_pub_hash mismatch.
	pub, _ := generateTestKeyPair(t)
	_, attackerPriv := generateTestKeyPair(t)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	serverErr := make(chan error, 1)
	clientErr := make(chan error, 1)
	go func() { serverErr <- serverHandshake(serverConn, pub) }()
	go func() {
		err := clientHandshake(clientConn, attackerPriv)
		clientConn.Close() // unblock server
		clientErr <- err
	}()

	err := <-clientErr
	if err == nil {
		t.Fatal("expected client to detect MITM")
	}
	if !strings.Contains(err.Error(), "server identity mismatch") {
		t.Fatalf("expected MITM detection error, got: %v", err)
	}

	// Server will fail due to pipe close
	<-serverErr
}

func TestHandshakeNoAuth(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	errs := make(chan error, 2)
	go func() { errs <- serverHandshake(serverConn, nil) }()
	go func() { errs <- clientHandshake(clientConn, nil) }()

	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("no-auth handshake error: %v", err)
		}
	}
}

func TestHandshakeTimeout(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	// Set a tight deadline on the server side, then never send from client
	serverConn.SetDeadline(time.Now().Add(50 * time.Millisecond))

	err := serverHandshake(serverConn, nil)
	// Should fail because the client never responds (pipe stays open but silent)
	// Actually the server sends the challenge first, then waits for response.
	// The client side is not running, so readMsg will block until deadline.
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestHandshakeServerNoAuthClientHasKey(t *testing.T) {
	// Server has no auth, client has a key. Should succeed (no-auth mode).
	_, priv := generateTestKeyPair(t)

	serverConn, clientConn := net.Pipe()

	errs := make(chan error, 2)
	go func() { errs <- serverHandshake(serverConn, nil) }()
	go func() { errs <- clientHandshake(clientConn, priv) }()

	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("handshake error: %v", err)
		}
	}
}

func TestHandshakeServerAuthClientNoKey(t *testing.T) {
	// Server requires auth, client has no key. Should fail.
	pub, _ := generateTestKeyPair(t)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	serverErr := make(chan error, 1)
	clientErr := make(chan error, 1)
	go func() {
		err := serverHandshake(serverConn, pub)
		serverConn.Close() // unblock client if needed
		serverErr <- err
	}()
	go func() { clientErr <- clientHandshake(clientConn, nil) }()

	sErr := <-serverErr
	cErr := <-clientErr
	if sErr == nil && cErr == nil {
		t.Fatal("expected handshake to fail when server requires auth but client has no key")
	}
}

func TestDeriveServerIdentity(t *testing.T) {
	pub, _ := generateTestKeyPair(t)

	// Same key produces same identity
	id1 := deriveServerIdentity(pub)
	id2 := deriveServerIdentity(pub)
	if string(id1) != string(id2) {
		t.Fatal("deriveServerIdentity not deterministic")
	}

	// Different key produces different identity
	pub2, _ := generateTestKeyPair(t)
	id3 := deriveServerIdentity(pub2)
	if string(id1) == string(id3) {
		t.Fatal("different keys produced same identity")
	}
}
