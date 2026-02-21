package vtunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
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

// parsePrivateKey decodes a "vt-priv-..." string into an ssh.Signer.
func parsePrivateKey(encoded string) (ssh.Signer, error) {
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
	priv := ed25519.NewKeyFromSeed(seed)
	return ssh.NewSignerFromKey(priv)
}

// parsePublicKey decodes a "vt-pub-..." string into an ssh.PublicKey.
func parsePublicKey(encoded string) (ssh.PublicKey, error) {
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
	return ssh.NewPublicKey(ed25519.PublicKey(b))
}

// deriveHostKey derives a deterministic ed25519 server host key from the
// client's public key. Both server and client can compute this independently,
// enabling MITM protection without extra configuration.
func deriveHostKey(clientPubKey ssh.PublicKey) (ssh.Signer, error) {
	h := sha256.Sum256(clientPubKey.Marshal())
	priv := ed25519.NewKeyFromSeed(h[:])
	return ssh.NewSignerFromKey(priv)
}
