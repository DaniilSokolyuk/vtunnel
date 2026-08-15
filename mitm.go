package vtunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"time"
)

const (
	// leafValidity is how long a generated leaf certificate stays valid.
	// Short-lived leaves keep a leaked one from being useful for long; the
	// cache renews them transparently.
	leafValidity = 7 * 24 * time.Hour

	// leafRenewBefore is how far ahead of expiry a cached leaf is regenerated,
	// so a long-lived connection never starts on a cert that expires mid-session.
	leafRenewBefore = 24 * time.Hour

	// leafBackdate tolerates clock skew between the proxy and its clients.
	leafBackdate = 24 * time.Hour

	// maxCachedCerts bounds the cache. Reached only by a client walking many
	// distinct SNI names; the sweep drops expired entries first.
	maxCachedCerts = 1024
)

// certCache generates and caches TLS certificates signed by a MITM CA.
type certCache struct {
	ca     tls.Certificate
	caX509 *x509.Certificate

	mu    sync.Mutex
	certs map[string]*cachedCert
}

type cachedCert struct {
	cert *tls.Certificate
	// renewAt is when the entry stops being handed out: leaf expiry minus
	// leafRenewBefore.
	renewAt time.Time
}

func newCertCache(ca tls.Certificate) (*certCache, error) {
	caX509, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, err
	}
	return &certCache{
		ca:     ca,
		caX509: caX509,
		certs:  make(map[string]*cachedCert),
	}, nil
}

// getCert returns a TLS certificate for the given ClientHello, generating one if needed.
// If SNI is absent, fallbackHost is used (for CONNECT authorities like host:port).
//
// Cached entries are regenerated once they approach expiry. Unlike gost, which
// re-verifies every cache hit against the CA pool, this cache only checks the
// clock: the CA is fixed for the lifetime of a certCache, so a hit can only
// ever fail verification by being expired, and a signature check on every
// handshake would be pure cost on the hot path.
func (c *certCache) getCert(hello *tls.ClientHelloInfo, fallbackHost string) (*tls.Certificate, error) {
	host := hello.ServerName
	if host == "" {
		host = fallbackHost
	}
	if host == "" {
		host = "localhost"
	}

	now := time.Now()

	c.mu.Lock()
	if cached, ok := c.certs[host]; ok {
		if now.Before(cached.renewAt) {
			c.mu.Unlock()
			return cached.cert, nil
		}
		delete(c.certs, host)
	}
	c.mu.Unlock()

	cert, notAfter, err := c.signHost(host, now)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	if len(c.certs) >= maxCachedCerts {
		c.sweepLocked(now)
	}
	c.certs[host] = &cachedCert{cert: cert, renewAt: notAfter.Add(-leafRenewBefore)}
	c.mu.Unlock()

	return cert, nil
}

// sweepLocked drops entries that are due for renewal. If that frees nothing —
// every entry is still fresh — the whole map is dropped rather than letting it
// grow without bound; the cost is regenerating certs that are still in use.
func (c *certCache) sweepLocked(now time.Time) {
	for host, cached := range c.certs {
		if !now.Before(cached.renewAt) {
			delete(c.certs, host)
		}
	}
	if len(c.certs) >= maxCachedCerts {
		clear(c.certs)
	}
}

// signHost generates a leaf TLS certificate for hostname, signed by the CA.
// It returns the certificate and its expiry.
//
// The leaf gets its own freshly generated key. gost instead signs the CA's own
// public key and hands out the CA private key with every leaf
// (x/internal/util/tls/tls.go:451); that saves a keygen per host at the cost of
// every leaf sharing the CA keypair, which is not a trade worth taking.
func (c *certCache) signHost(hostname string, now time.Time) (*tls.Certificate, time.Time, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, time.Time{}, err
	}

	// A random 128-bit serial, not a timestamp: serials must be unpredictable
	// and collision-free.
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, time.Time{}, err
	}

	notAfter := now.Add(leafValidity)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    now.Add(-leafBackdate),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(hostname); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{hostname}
	}

	// SignatureAlgorithm is deliberately left unset so it is derived from the
	// CA key. Pinning it (gost hardcodes SHA256WithRSA) would reject EC CAs.
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, c.caX509, &key.PublicKey, c.ca.PrivateKey)
	if err != nil {
		return nil, time.Time{}, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER, c.ca.Certificate[0]},
		PrivateKey:  key,
	}, notAfter, nil
}
