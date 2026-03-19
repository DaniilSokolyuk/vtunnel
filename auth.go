package vtunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"strings"
)

const (
	privKeyPrefix = "vt-priv-"
	pubKeyPrefix  = "vt-pub-"
)

// GenerateKeyPair generates an ed25519 keypair and returns encoded strings.
// The private key ("vt-priv-...") should be kept secret on the client.
// The public key ("vt-pub-...") is safe to store on the server.
func GenerateKeyPair() (privKey, pubKey string, err error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return "", "", fmt.Errorf("generate seed: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	privKey = privKeyPrefix + base64.RawStdEncoding.EncodeToString(seed)
	pubKey = pubKeyPrefix + base64.RawStdEncoding.EncodeToString(pub)
	return privKey, pubKey, nil
}

// parsePrivateKey decodes a "vt-priv-..." string into an ed25519.PrivateKey.
func parsePrivateKey(encoded string) (ed25519.PrivateKey, error) {
	raw, ok := strings.CutPrefix(encoded, privKeyPrefix)
	if !ok {
		return nil, fmt.Errorf("private key must start with %q", privKeyPrefix)
	}
	seed, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid private key length: %d", len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// parsePublicKey decodes a "vt-pub-..." string into an ed25519.PublicKey.
func parsePublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, ok := strings.CutPrefix(encoded, pubKeyPrefix)
	if !ok {
		return nil, fmt.Errorf("public key must start with %q", pubKeyPrefix)
	}
	b, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: %d", len(b))
	}
	return ed25519.PublicKey(b), nil
}

// deriveServerIdentity returns SHA256(raw ed25519 public key bytes).
// Both server and client can compute this independently from the client's
// public key, enabling MITM protection without extra configuration.
func deriveServerIdentity(clientPubKey ed25519.PublicKey) []byte {
	h := sha256.Sum256(clientPubKey)
	return h[:]
}

// Handshake message types for the custom ed25519 challenge-response auth protocol.

type authChallenge struct {
	Challenge     string `json:"challenge"`       // base64, 32 random bytes
	ServerPubHash string `json:"server_pub_hash"` // base64, SHA256(client_pubkey_bytes)
}

type authResponse struct {
	Signature string `json:"signature"`  // base64, ed25519 signature over raw challenge
	ClientPub string `json:"client_pub"` // base64, ed25519 public key (32 bytes)
}

type authResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// serverHandshake performs the server side of the custom auth handshake.
// clientPubKey is nil for no-auth mode.
func serverHandshake(conn net.Conn, clientPubKey ed25519.PublicKey) error {
	// Step 1: Send challenge
	var ch authChallenge
	if clientPubKey != nil {
		challengeBytes := make([]byte, 32)
		if _, err := rand.Read(challengeBytes); err != nil {
			return fmt.Errorf("generate challenge: %w", err)
		}
		ch.Challenge = base64.StdEncoding.EncodeToString(challengeBytes)
		ch.ServerPubHash = base64.StdEncoding.EncodeToString(deriveServerIdentity(clientPubKey))
	} else {
		log.Println("[vtunnel-server] WARNING: Authentication is DISABLED")
	}
	if err := writeMsg(conn, ch); err != nil {
		return fmt.Errorf("send challenge: %w", err)
	}

	// Step 2: Read response
	var resp authResponse
	if err := readMsg(conn, &resp); err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	// Step 3: Verify and send result
	if clientPubKey == nil {
		return writeMsg(conn, authResult{OK: true})
	}

	// Decode client public key
	clientPubBytes, err := base64.StdEncoding.DecodeString(resp.ClientPub)
	if err != nil || len(clientPubBytes) != ed25519.PublicKeySize {
		writeMsg(conn, authResult{OK: false, Error: "unauthorized key"})
		return fmt.Errorf("invalid client public key")
	}

	// Verify key matches expected
	receivedPub := ed25519.PublicKey(clientPubBytes)
	if !receivedPub.Equal(clientPubKey) {
		writeMsg(conn, authResult{OK: false, Error: "unauthorized key"})
		return fmt.Errorf("unauthorized key")
	}

	// Verify signature
	challengeBytes, err := base64.StdEncoding.DecodeString(ch.Challenge)
	if err != nil {
		writeMsg(conn, authResult{OK: false, Error: "internal error"})
		return fmt.Errorf("decode challenge: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		writeMsg(conn, authResult{OK: false, Error: "invalid signature"})
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(receivedPub, challengeBytes, sig) {
		writeMsg(conn, authResult{OK: false, Error: "invalid signature"})
		return fmt.Errorf("invalid signature")
	}

	return writeMsg(conn, authResult{OK: true})
}

// clientHandshake performs the client side of the custom auth handshake.
// privKey is nil for no-auth mode.
func clientHandshake(conn net.Conn, privKey ed25519.PrivateKey) error {
	// Step 1: Read challenge
	var ch authChallenge
	if err := readMsg(conn, &ch); err != nil {
		return fmt.Errorf("read challenge: %w", err)
	}

	// Step 2: Build and send response
	var resp authResponse
	if ch.Challenge == "" {
		// No-auth mode: server doesn't require authentication
		log.Println("[vtunnel-client] WARNING: Authentication is DISABLED")
	} else if privKey == nil {
		// Server requires auth but client has no key — send empty response, server will reject
	} else {
		// Full auth: verify server identity and sign challenge
		pubKey := privKey.Public().(ed25519.PublicKey)
		expectedHash := base64.StdEncoding.EncodeToString(deriveServerIdentity(pubKey))
		if ch.ServerPubHash != expectedHash {
			return fmt.Errorf("server identity mismatch (possible MITM)")
		}

		challengeBytes, err := base64.StdEncoding.DecodeString(ch.Challenge)
		if err != nil {
			return fmt.Errorf("decode challenge: %w", err)
		}
		sig := ed25519.Sign(privKey, challengeBytes)
		resp.Signature = base64.StdEncoding.EncodeToString(sig)
		resp.ClientPub = base64.StdEncoding.EncodeToString(pubKey)
	}

	if err := writeMsg(conn, resp); err != nil {
		return fmt.Errorf("send response: %w", err)
	}

	// Step 3: Read result
	var result authResult
	if err := readMsg(conn, &result); err != nil {
		return fmt.Errorf("read result: %w", err)
	}
	if !result.OK {
		return fmt.Errorf("auth failed: %s", result.Error)
	}
	return nil
}
