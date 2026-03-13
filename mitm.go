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

// certCache generates and caches TLS certificates signed by a MITM CA.
type certCache struct {
	ca     tls.Certificate
	caX509 *x509.Certificate
	certs  sync.Map // hostname -> *tls.Certificate
}

func newCertCache(ca tls.Certificate) (*certCache, error) {
	caX509, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, err
	}
	return &certCache{ca: ca, caX509: caX509}, nil
}

// getCert returns a TLS certificate for the given ClientHello, generating one if needed.
// If SNI is absent, fallbackHost is used (for CONNECT authorities like host:port).
func (c *certCache) getCert(hello *tls.ClientHelloInfo, fallbackHost string) (*tls.Certificate, error) {
	host := hello.ServerName
	if host == "" {
		host = fallbackHost
	}
	if host == "" {
		host = "localhost"
	}
	if cached, ok := c.certs.Load(host); ok {
		return cached.(*tls.Certificate), nil
	}
	cert, err := c.signHost(host)
	if err != nil {
		return nil, err
	}
	c.certs.Store(host, cert)
	return cert, nil
}

// signHost generates a leaf TLS certificate for hostname, signed by the CA.
func (c *certCache) signHost(hostname string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now().Add(-30 * 24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(hostname); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{hostname}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, c.caX509, &key.PublicKey, c.ca.PrivateKey)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER, c.ca.Certificate[0]},
		PrivateKey:  key,
	}, nil
}
