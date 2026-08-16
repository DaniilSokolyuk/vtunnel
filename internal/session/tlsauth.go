package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/vivid-money/vtunnel/internal/tunnelkey"
)

// A multiplexer brings no cryptography of its own, so anything that is not SSH
// needs some put back underneath it. This is TLS 1.3 with both ends' keys
// pinned — the same two identities the SSH backend uses, wrapped in the
// smallest certificate that will carry them.
//
// TLS rather than Noise on purpose. Noise would be a smaller handshake and a
// new dependency, but its Go libraries hand back cipher states, not a
// net.Conn: the record layer — framing, nonce sequencing, rekeying before
// exhaustion — would be ours to write, and that is precisely where cryptography
// goes wrong quietly. crypto/tls is in the standard library and its record
// layer is not ours.
//
// Verification is pinning and nothing else: not the chain, not the name, not
// the validity window. That keeps a sandbox with a wrong clock working, which
// matters more here than an expiry date on a certificate nobody issued.

const tlsALPN = "vtunnel/1"

// secureClient and secureServer turn any transport into an authenticated one.
//
// They belong here rather than inside a backend: a multiplexer's business is
// multiplexing, and the next one added should inherit the tunnel's
// authentication without reimplementing it. SSH is the exception that proves
// it — the one backend that brings its own, and so the one that skips this.
func secureClient(conn net.Conn, cfg Config) (net.Conn, error) {
	tc, err := tlsClientConfig(cfg.Keys)
	if err != nil {
		return nil, err
	}
	sec := tls.Client(conn, tc)
	if err := sec.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	if err := clientHello(sec); err != nil {
		return nil, err
	}
	return sec, nil
}

func secureServer(conn net.Conn, cfg Config) (net.Conn, error) {
	tc, err := tlsServerConfig(cfg.Keys)
	if err != nil {
		return nil, err
	}
	sec := tls.Server(conn, tc)
	if err := sec.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	if err := serverHello(sec); err != nil {
		return nil, err
	}
	return sec, nil
}

// tlsClientConfig authenticates this end as the client and pins the host key.
func tlsClientConfig(keys *tunnelkey.Keys) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{tlsALPN},
		// Pinning replaces verification wholesale; see pinnedTo.
		InsecureSkipVerify: true,
	}
	if keys == nil {
		// Unauthenticated mode: encrypted against a passive listener, worth
		// nothing against an active one. Same bargain the SSH backend strikes
		// without a secret, and the caller has already said so out loud.
		return cfg, nil
	}

	cert, err := keys.ClientCert()
	if err != nil {
		return nil, err
	}
	cfg.Certificates = []tls.Certificate{cert}
	cfg.VerifyPeerCertificate = pinnedTo(keys.Host.Public().(ed25519.PublicKey), "server")
	return cfg, nil
}

// tlsServerConfig authenticates this end as the host and pins the client key.
func tlsServerConfig(keys *tunnelkey.Keys) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{tlsALPN},
	}
	if keys == nil {
		cert, err := ephemeralCert()
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
		return cfg, nil
	}

	cert, err := keys.HostCert()
	if err != nil {
		return nil, err
	}
	cfg.Certificates = []tls.Certificate{cert}
	cfg.ClientAuth = tls.RequireAnyClientCert
	cfg.VerifyPeerCertificate = pinnedTo(keys.Client.Public().(ed25519.PublicKey), "client")
	return cfg, nil
}

// pinnedTo accepts exactly one public key and refuses everything else. role
// names the peer so the failure says which end went wrong.
func pinnedTo(expected ed25519.PublicKey, role string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("%s presented no certificate", role)
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("%s certificate: %w", role, err)
		}
		got, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok || !got.Equal(expected) {
			return fmt.Errorf("%s key mismatch: the peer does not hold this tunnel's secret", role)
		}
		return nil
	}
}

// ephemeralCert backs the unauthenticated mode, where the certificate proves
// nothing and one per process is as good as one per connection.
var ephemeralCert = sync.OnceValues(func() (tls.Certificate, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tunnelkey.SelfSigned(key)
})

// helloByte is exchanged once, both ways, before the multiplexer starts.
//
// TLS 1.3 has the client finish its handshake before the server has looked at
// the client's certificate, so a client holding the wrong secret would believe
// it had connected and only find out on some later read. One byte each way
// turns that into an error from Dial, where the caller can see it.
const helloByte = 'v'

func clientHello(conn net.Conn) error {
	if _, err := conn.Write([]byte{helloByte}); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}
	var b [1]byte
	if _, err := conn.Read(b[:]); err != nil {
		return fmt.Errorf("await hello: %w", err)
	}
	if b[0] != helloByte {
		return errors.New("peer is not a vtunnel session")
	}
	return nil
}

func serverHello(conn net.Conn) error {
	var b [1]byte
	if _, err := conn.Read(b[:]); err != nil {
		return fmt.Errorf("await hello: %w", err)
	}
	if b[0] != helloByte {
		return errors.New("peer is not a vtunnel session")
	}
	if _, err := conn.Write([]byte{helloByte}); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}
	return nil
}
