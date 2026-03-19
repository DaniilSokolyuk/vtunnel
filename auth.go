package vtunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	privKeyPrefix = "vt-priv-"
	pubKeyPrefix  = "vt-pub-"
	authScheme    = "VTunnel"
	authMaxAge    = 60 // seconds
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

// generateAuthToken creates an Authorization header value:
// "VTunnel <base64(pubkey)>.<base64(signature)>.<timestamp>"
func generateAuthToken(privKey ed25519.PrivateKey) string {
	if privKey == nil {
		return ""
	}
	pubKey := privKey.Public().(ed25519.PublicKey)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := ed25519.Sign(privKey, []byte(ts))
	return fmt.Sprintf("%s %s.%s.%s",
		authScheme,
		base64.RawURLEncoding.EncodeToString(pubKey),
		base64.RawURLEncoding.EncodeToString(sig),
		ts,
	)
}

// validateAuthToken validates an Authorization header value against the expected public key.
// Returns true if the token is valid (correct key, valid signature, fresh timestamp).
func validateAuthToken(header string, expectedPub ed25519.PublicKey) bool {
	if expectedPub == nil {
		return true // no auth required
	}

	after, ok := strings.CutPrefix(header, authScheme+" ")
	if !ok {
		return false
	}

	parts := strings.SplitN(after, ".", 3)
	if len(parts) != 3 {
		return false
	}

	pubBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	ts := parts[2]

	// Verify pubkey matches expected
	pub := ed25519.PublicKey(pubBytes)
	if !pub.Equal(expectedPub) {
		return false
	}

	// Verify signature over timestamp
	if !ed25519.Verify(pub, []byte(ts), sig) {
		return false
	}

	// Verify timestamp freshness
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	diff := time.Now().Unix() - tsInt
	if diff < 0 {
		diff = -diff
	}
	return diff <= authMaxAge
}
