package vtunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"sort"
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

// keyLogOnce guards the one-time resolution of tlsKeyLogWriter. Tests reset it
// to observe both outcomes.
var (
	keyLogOnce sync.Once
	keyLogDest io.Writer
)

// tlsKeyLogWriter returns where TLS session keys should be written, or nil when
// $SSLKEYLOGFILE is unset — which is what tls.Config expects for "off".
//
// Handing the keys over makes an intercepted session readable in Wireshark,
// which is the only practical way to see what actually went over a MITM'd
// connection. It also makes every session it covers readable by anyone who can
// read the file, so the mode belongs on a developer's machine and nowhere else.
// The file is opened 0600 rather than the 0666 the convention often uses.
func tlsKeyLogWriter() io.Writer {
	keyLogOnce.Do(func() {
		path := os.Getenv("SSLKEYLOGFILE")
		if path == "" {
			return
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			log.Printf("[vtunnel-proxy] SSLKEYLOGFILE=%s could not be opened, TLS key logging is off: %v", path, err)
			return
		}
		log.Printf("[vtunnel-proxy] WARNING: writing TLS session keys to %s — anyone who can read it can decrypt this traffic", path)
		keyLogDest = f
	})
	return keyLogDest
}

// certCache generates and caches TLS certificates signed by a MITM CA.
type certCache struct {
	ca     tls.Certificate
	caX509 *x509.Certificate

	mu       sync.Mutex
	certs    map[string]*cachedCert
	inflight map[string]*certRequest
}

type cachedCert struct {
	cert *tls.Certificate
	// renewAt is when the entry stops being handed out: leaf expiry minus
	// leafRenewBefore.
	renewAt time.Time
}

// certRequest is a signHost call in progress. Everyone who wants the same host
// while it runs waits on done instead of generating a second key; the fields are
// written before done is closed, so a waiter reading them after the receive sees
// the finished values.
type certRequest struct {
	done chan struct{}
	cert *tls.Certificate
	err  error
}

func newCertCache(ca tls.Certificate) (*certCache, error) {
	caX509, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, err
	}
	return &certCache{
		ca:       ca,
		caX509:   caX509,
		certs:    make(map[string]*cachedCert),
		inflight: make(map[string]*certRequest),
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
//
// Misses for the same host are deduplicated. A client opening several connections
// at once — which is the normal way a browser or `git` starts — would otherwise
// land as many simultaneous misses, each generating a key and all but one of
// those thrown away.
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
	if req, ok := c.inflight[host]; ok {
		c.mu.Unlock()
		<-req.done
		return req.cert, req.err
	}
	req := &certRequest{done: make(chan struct{})}
	c.inflight[host] = req
	c.mu.Unlock()

	cert, notAfter, err := c.signHost(host, now)

	c.mu.Lock()
	// Cleared in both outcomes: a failure must not pin the host to that error,
	// the next handshake should try again.
	delete(c.inflight, host)
	if err == nil {
		if len(c.certs) >= maxCachedCerts {
			c.sweepLocked(now)
		}
		c.certs[host] = &cachedCert{cert: cert, renewAt: notAfter.Add(-leafRenewBefore)}
	}
	c.mu.Unlock()

	req.cert, req.err = cert, err
	close(req.done)

	return cert, err
}

// sweepLocked makes room in a full cache. Entries due for renewal go first,
// since they are worthless anyway. If that frees nothing — every entry is still
// fresh — the oldest quarter is evicted by expiry, which is insertion order for
// leaves that all live equally long.
//
// Dropping the whole map instead, which is what this did, made a client walking
// distinct SNI names cost every other client on the proxy a fresh key on its
// next handshake: one cache overflow, and every live domain has to be signed
// again. Partial eviction keeps that a local cost.
func (c *certCache) sweepLocked(now time.Time) {
	for host, cached := range c.certs {
		if !now.Before(cached.renewAt) {
			delete(c.certs, host)
		}
	}
	if len(c.certs) < maxCachedCerts {
		return
	}

	evict := len(c.certs) / 4
	if evict == 0 {
		evict = 1
	}
	hosts := make([]string, 0, len(c.certs))
	for host := range c.certs {
		hosts = append(hosts, host)
	}
	sort.Slice(hosts, func(i, j int) bool {
		return c.certs[hosts[i]].renewAt.Before(c.certs[hosts[j]].renewAt)
	})
	for _, host := range hosts[:evict] {
		delete(c.certs, host)
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
		// DigitalSignature only: the leaf key is ECDSA, and there is no key
		// transport in ECDHE for KeyEncipherment to authorise. Setting it is
		// harmless in practice but strict validators object.
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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
