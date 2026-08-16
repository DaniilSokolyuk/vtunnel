// Package tunnelkey turns the one string an operator configures into the key
// material both ends of the tunnel authenticate with.
//
// It sits below both the public API and the session backends, which is why it
// is a package of its own: a session needs the keys, and the public API needs
// the session, so the keys cannot live in either.
package tunnelkey

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh"
)

const (
	// WeakLen is where a secret stops being worth a warning. Length is a poor
	// stand-in for entropy, but it is the only one available for a string
	// someone chose, and it catches the values people reach for first.
	WeakLen = 16

	// Both ends of the tunnel derive their keys from the same secret, so the
	// two derivations must not be able to collide: the client would otherwise
	// be indistinguishable from the server it is authenticating.
	clientKeyInfo = "vtunnel client key v1"
	hostKeyInfo   = "vtunnel host key v1"

	// stretchSalt is fixed because both ends must derive the same keys from the
	// secret alone, with nothing exchanged first. Argon2's memory hardness is
	// what carries the weight here, not the salt.
	stretchSalt = "vtunnel tunnel secret v1"

	// Argon2id parameters: the second profile recommended by RFC 9106. Applied
	// once per process at startup, never per connection, so the cost lands on
	// whoever is guessing rather than on the tunnel. The 64 MiB is transient
	// and is what makes guessing on a GPU unattractive.
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
)

// Keys are the two identities of one tunnel. Both ends hold both: the secret is
// symmetric, so each side proves itself with one and pins the peer to the other.
//
// Which is which is fixed by role, not by who generated it — the dialling side
// signs with Client and expects Host from the peer, and the listening side does
// the reverse.
type Keys struct {
	Client ed25519.PrivateKey
	Host   ed25519.PrivateKey

	// Derived presentations of the same two keys, computed on first use.
	//
	// A session handshake needs them, and a tunnel handshakes again on every
	// reconnect — a sandbox on a flapping link does so repeatedly. Signing a
	// fresh certificate each time is work with no result that differs, so it
	// happens once.
	once       sync.Once
	clientCert tls.Certificate
	hostCert   tls.Certificate
	clientSSH  ssh.Signer
	hostSSH    ssh.Signer
	derivedErr error
}

// Warning describes what is wrong with a secret, or returns "" if there is
// nothing to say. Nothing is refused: a secret is whatever the operator decided
// it is, and being unable to start is worse than being told.
func Warning(secret string) string {
	if len(secret) < WeakLen {
		return fmt.Sprintf("this tunnel secret is short enough to guess (%d characters, %d recommended). "+
			"Anyone who can reach this tunnel can collect the key it derives and try secrets "+
			"against it offline — no rate limit, nothing to alert on", len(secret), WeakLen)
	}
	return ""
}

// Derive turns one shared secret into the two ed25519 identities the tunnel
// authenticates with.
//
// Both sides compute both keys, which is what makes a single configured value
// enough. Neither can be computed by anyone else, which is what makes the
// pinning real — the predecessor of this function derived the host key from the
// client's public key, a value published in sandbox images and CI variables, so
// any reader of it could impersonate the server.
//
// The secret is stretched with Argon2id first, which is what lets it be an
// ordinary string rather than a fixed-width blob. Whatever the session backend,
// an attacker who can merely dial the sandbox ends up holding a value derived
// from the secret — SSH hands out the host public key during key exchange, and
// a TLS server sends its certificate to anyone who completes ECDHE with it. So
// candidate secrets can always be tested offline, unsalted and unthrottled.
// Argon2id turns each of those guesses from a microsecond into ~25 ms and
// 64 MiB, and the memory keeps it that expensive on a GPU too. It runs once per
// process, at startup, never per connection.
//
// It buys roughly sixteen bits, which is worth having and is not a substitute
// for entropy: 32 random bytes are out of reach without it, and a memorable
// phrase stays in reach with it.
func Derive(secret string) (*Keys, error) {
	if cached, ok := derived.Load(secret); ok {
		return cached.(*Keys), nil
	}
	keys, err := derive(secret)
	if err != nil {
		return nil, err
	}
	derived.Store(secret, keys)
	return keys, nil
}

// derived memoises Derive. The stretch is deliberately expensive — 64 MiB and
// ~25 ms — and paying it twice for the same string buys nothing: the result is
// a pure function of the input. It matters wherever more than one Client or
// Server is built from one secret, which a test, a benchmark and a
// controlplane that reconstructs its client all do.
//
// The keys stay for the life of the process. They were derived from a secret
// the process is already holding, so this gives away nothing it did not
// already have.
var derived sync.Map // secret string -> *Keys

func derive(secret string) (*Keys, error) {
	master := argon2.IDKey([]byte(secret), []byte(stretchSalt), argonTime, argonMemory, argonThreads, ed25519.SeedSize)

	client, err := deriveKey(master, clientKeyInfo)
	if err != nil {
		return nil, err
	}
	host, err := deriveKey(master, hostKeyInfo)
	if err != nil {
		return nil, err
	}
	return &Keys{Client: client, Host: host}, nil
}

func deriveKey(master []byte, info string) (ed25519.PrivateKey, error) {
	seed, err := hkdf.Key(sha256.New, master, nil, info, ed25519.SeedSize)
	if err != nil {
		return nil, fmt.Errorf("derive %s: %w", info, err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// ClientSigner and HostSigner present the keys to golang.org/x/crypto/ssh.
func (k *Keys) ClientSigner() (ssh.Signer, error) { return k.clientSSH, k.derive() }
func (k *Keys) HostSigner() (ssh.Signer, error)   { return k.hostSSH, k.derive() }

// ClientCert and HostCert present the keys to crypto/tls.
//
// The certificate is the smallest thing TLS will carry a public key in. Its
// contents are never read: the peer compares the key against the one it derived
// from the same secret and stops there, so there is no name to match, no chain
// to build and no validity window to be on the wrong side of. That last part is
// deliberate — a sandbox with a wrong clock is a real thing, and an expiry date
// on a certificate nobody issued would only break it.
func (k *Keys) ClientCert() (tls.Certificate, error) { return k.clientCert, k.derive() }
func (k *Keys) HostCert() (tls.Certificate, error)   { return k.hostCert, k.derive() }

func (k *Keys) derive() error {
	k.once.Do(func() {
		var err error
		if k.clientSSH, err = ssh.NewSignerFromKey(k.Client); err != nil {
			k.derivedErr = fmt.Errorf("client signer: %w", err)
			return
		}
		if k.hostSSH, err = ssh.NewSignerFromKey(k.Host); err != nil {
			k.derivedErr = fmt.Errorf("host signer: %w", err)
			return
		}
		if k.clientCert, err = selfSigned(k.Client); err != nil {
			k.derivedErr = fmt.Errorf("client certificate: %w", err)
			return
		}
		if k.hostCert, err = selfSigned(k.Host); err != nil {
			k.derivedErr = fmt.Errorf("host certificate: %w", err)
		}
	})
	return k.derivedErr
}

func selfSigned(key ed25519.PrivateKey) (tls.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "vtunnel"},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Date(2999, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// SelfSigned wraps any ed25519 key the same way, for the unauthenticated mode
// where the certificate proves nothing and only has to exist.
func SelfSigned(key ed25519.PrivateKey) (tls.Certificate, error) { return selfSigned(key) }
