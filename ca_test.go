package vtunnel

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

// CACertPEM is what separates the half that may enter a sandbox from the half
// that must not. If it ever emits key material, every sandbox that installed
// the output holds a CA that can mint trusted certificates.
func TestCACertPEMDropsThePrivateKey(t *testing.T) {
	blob, err := GenerateCA("vtunnel test CA")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if !strings.Contains(string(blob), "PRIVATE KEY") {
		t.Fatal("generated CA blob has no private key; the fixture is wrong")
	}

	certOnly, err := CACertPEM(blob)
	if err != nil {
		t.Fatalf("CACertPEM: %v", err)
	}
	if strings.Contains(string(certOnly), "PRIVATE KEY") {
		t.Fatalf("CACertPEM leaked key material:\n%s", certOnly)
	}
	if !strings.Contains(string(certOnly), "BEGIN CERTIFICATE") {
		t.Fatalf("CACertPEM returned no certificate:\n%s", certOnly)
	}

	// And the surviving half must still be a usable CA.
	ca, err := LoadCA(blob)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if !ca.Leaf.IsCA {
		t.Fatal("generated certificate is not a CA")
	}
	if ca.Leaf.Subject.CommonName != "vtunnel test CA" {
		t.Fatalf("CommonName = %q", ca.Leaf.Subject.CommonName)
	}
}

// A non-CA certificate must be rejected rather than silently used, otherwise
// interception fails later with an opaque signing error.
func TestLoadCARejectsNonCA(t *testing.T) {
	ca, err := GenerateCA("issuer")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	parsed, err := LoadCA(ca)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	cache, err := newCertCache(parsed)
	if err != nil {
		t.Fatalf("newCertCache: %v", err)
	}
	leaf, _, err := cache.signHost("leaf.test", time.Now())
	if err != nil {
		t.Fatalf("signHost: %v", err)
	}
	if _, err := LoadCA(pemOf(t, leaf.Certificate[0])); err == nil {
		t.Fatal("LoadCA accepted a leaf certificate as a CA")
	}
}

func pemOf(t *testing.T, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// The leaf's signature algorithm is derived from the CA key rather than pinned,
// so both EC and RSA CAs work. gost hardcodes SHA256WithRSA
// (x/internal/util/tls/tls.go), which rejects an EC CA outright — and an EC CA
// is what `vtunnel ca` produces.
func TestCertCacheSignsWithEitherCAKeyType(t *testing.T) {
	ecBlob, err := GenerateCA("ec CA")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	ecCA, err := LoadCA(ecBlob)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	for _, tc := range []struct {
		name string
		ca   tls.Certificate
		want x509.PublicKeyAlgorithm
	}{
		{name: "EC CA", ca: ecCA, want: x509.ECDSA},
		{name: "RSA CA", ca: rsaTestCA(t), want: x509.RSA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache, err := newCertCache(tc.ca)
			if err != nil {
				t.Fatalf("newCertCache: %v", err)
			}
			cert, err := cache.getCert(&tls.ClientHelloInfo{ServerName: "leaf.test"}, "")
			if err != nil {
				t.Fatalf("getCert: %v", err)
			}
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatalf("parse leaf: %v", err)
			}

			roots := x509.NewCertPool()
			roots.AddCert(cache.caX509)
			if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "leaf.test", Roots: roots}); err != nil {
				t.Fatalf("leaf does not chain to the %s: %v", tc.name, err)
			}
			if got := cache.caX509.PublicKeyAlgorithm; got != tc.want {
				t.Fatalf("CA key algorithm = %v, want %v", got, tc.want)
			}
		})
	}
}

// A client opening several connections to the same host at once is the normal
// case, not the exceptional one — browsers and `git` both do it. Each of those
// handshakes calls getCert, and before the misses were deduplicated they all
// generated their own key and leaf, with every result but the last thrown away.
func TestCertCacheDeduplicatesConcurrentMisses(t *testing.T) {
	blob, err := GenerateCA("dedup CA")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	ca, err := LoadCA(blob)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	cache, err := newCertCache(ca)
	if err != nil {
		t.Fatalf("newCertCache: %v", err)
	}

	const callers = 50
	var wg sync.WaitGroup
	certs := make([]*tls.Certificate, callers)
	errs := make([]error, callers)
	start := make(chan struct{})

	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release them together, so they really do collide
			certs[i], errs[i] = cache.getCert(&tls.ClientHelloInfo{ServerName: "busy.test"}, "")
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: getCert: %v", i, err)
		}
	}
	// One generated certificate means one key: identity of the pointer is the
	// assertion, since every signHost call would produce a distinct one.
	for i, cert := range certs {
		if cert != certs[0] {
			t.Fatalf("caller %d got a different certificate — the miss was not deduplicated", i)
		}
	}

	cache.mu.Lock()
	inflight := len(cache.inflight)
	cache.mu.Unlock()
	if inflight != 0 {
		t.Fatalf("inflight has %d leftover entries, want 0", inflight)
	}
}

// A failure must reach every waiter and leave nothing behind: if the in-progress
// entry survived, the host would be pinned to that error and no later handshake
// could ever recover.
func TestCertCacheFailureReachesAllWaitersAndClears(t *testing.T) {
	blob, err := GenerateCA("failing CA")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	ca, err := LoadCA(blob)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	cache, err := newCertCache(ca)
	if err != nil {
		t.Fatalf("newCertCache: %v", err)
	}
	// Signing needs the CA private key; without it x509.CreateCertificate fails.
	cache.ca.PrivateKey = nil

	const callers = 10
	var wg sync.WaitGroup
	errs := make([]error, callers)
	start := make(chan struct{})

	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, errs[i] = cache.getCert(&tls.ClientHelloInfo{ServerName: "broken.test"}, "")
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err == nil {
			t.Fatalf("caller %d got no error, want the signing failure", i)
		}
	}

	cache.mu.Lock()
	inflight, cached := len(cache.inflight), len(cache.certs)
	cache.mu.Unlock()
	if inflight != 0 {
		t.Fatalf("inflight has %d leftover entries after a failure, want 0", inflight)
	}
	if cached != 0 {
		t.Fatalf("cache holds %d entries after a failure, want 0", cached)
	}

	// With the key back, the host must be signable again rather than stuck.
	cache.ca.PrivateKey = ca.PrivateKey
	if _, err := cache.getCert(&tls.ClientHelloInfo{ServerName: "broken.test"}, ""); err != nil {
		t.Fatalf("host stayed poisoned after the failure cleared: %v", err)
	}
}

func rsaTestCA(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rsa CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create RSA CA: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
