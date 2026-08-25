package tunnelkey

// Where the two tunnel identities come from.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
)

func mustDerive(t *testing.T, secret string) *Keys {
	t.Helper()
	k, err := Derive(secret)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pub(k ed25519.PrivateKey) []byte { return k.Public().(ed25519.PublicKey) }

// The bug this replaces: the host key was ed25519(sha256(clientPublicKey)), and
// the client public key was published in sandbox images and CI variables. Any
// reader of it could sign as the server, so the client's pinning check proved
// only that the peer had read something public.
//
// Nothing derived from a public value may reproduce the host key.
func TestHostKeyIsNotAFunctionOfTheClientKey(t *testing.T) {
	k := mustDerive(t, "4TFuXPmXvZ4dQ1cKQ0hR2sB9wN6yE3jL")

	seed := sha256.Sum256(pub(k.Client))
	forged := ed25519.NewKeyFromSeed(seed[:])
	if bytes.Equal(pub(forged), pub(k.Host)) {
		t.Fatal("the host key is derivable from the client's public key: " +
			"anyone holding the published key can impersonate the server")
	}
}

// The two identities share one secret, so the domain separation in the KDF is
// the only thing keeping them apart. Were the info strings ever to converge,
// the client and the server would present the same key and each would happily
// authenticate itself.
func TestTheTwoIdentitiesAreDistinct(t *testing.T) {
	k := mustDerive(t, "9pW2vK7mQ4xR1tY8uB3nC6dF0gH5jL")
	if bytes.Equal(pub(k.Client), pub(k.Host)) {
		t.Fatal("client and host keys are identical; the KDF lost its domain separation")
	}
}

// Same secret, same keys — this is what lets one configured value stand in for
// a distributed keypair.
func TestDerivationIsDeterministic(t *testing.T) {
	const secret = "2hG8kL4nP7qS1vX5zA9bD3fJ6mR0tW"

	a := mustDerive(t, secret)
	b := mustDerive(t, secret)
	if !bytes.Equal(pub(a.Client), pub(b.Client)) {
		t.Error("client key differs between derivations from the same secret")
	}
	if !bytes.Equal(pub(a.Host), pub(b.Host)) {
		t.Error("host key differs between derivations from the same secret")
	}
}

// Different secrets must not collide, or one sandbox could pose as another.
func TestDifferentSecretsGiveDifferentIdentities(t *testing.T) {
	a := mustDerive(t, "7bN3xV9cM2kQ5wZ8tR1yU4aE6sD0fG")
	b := mustDerive(t, "1aY6uT2rE8wQ4oP0iL5kJ9hG3fD7sA")
	if bytes.Equal(pub(a.Client), pub(b.Client)) {
		t.Error("two secrets produced the same client key")
	}
	if bytes.Equal(pub(a.Host), pub(b.Host)) {
		t.Error("two secrets produced the same host key")
	}
}

// Nothing is refused, but a secret people reach for first is called out.
func TestWarning(t *testing.T) {
	if Warning("hunter2") == "" {
		t.Error("a 7-character secret should be warned about")
	}
	if w := Warning("8Kq2vX7mR4nP1tY5uB9cD3fJ6wZ0aE"); w != "" {
		t.Errorf("a 30-character secret should pass without comment, got: %s", w)
	}
}
