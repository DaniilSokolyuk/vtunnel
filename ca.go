package vtunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// caValidity is how long a generated MITM CA stays usable.
const caValidity = 10 * 365 * 24 * time.Hour

// GenerateCA creates a self-signed CA for MITM interception and returns it as a
// single PEM blob holding the certificate followed by its private key.
//
// The blob belongs on the controlplane and nowhere else. Only the certificate
// half — see CACertPEM — should ever reach a sandbox.
func GenerateCA(commonName string) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate CA serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-leafBackdate),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal CA key: %w", err)
	}

	blob := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	blob = append(blob, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	return blob, nil
}

// CACertPEM returns only the CERTIFICATE blocks of a CA PEM blob — the half
// that is safe to install in a sandbox trust store.
func CACertPEM(blob []byte) ([]byte, error) {
	var out []byte
	rest := blob
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			out = append(out, pem.EncodeToMemory(block)...)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE block found")
	}
	return out, nil
}

// LoadCA parses a PEM blob holding a certificate and its private key into a
// tls.Certificate with Leaf populated, ready for WithMitmCA.
func LoadCA(blob []byte) (tls.Certificate, error) {
	cert, err := tls.X509KeyPair(blob, blob)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse CA cert+key: %w", err)
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse CA leaf: %w", err)
	}
	if !cert.Leaf.IsCA {
		return tls.Certificate{}, fmt.Errorf("certificate is not a CA")
	}
	return cert, nil
}
