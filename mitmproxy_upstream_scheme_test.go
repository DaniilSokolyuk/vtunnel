package vtunnel_test

// Whether the upstream speaks TLS is a fact about the upstream, not something
// to read off its port number. Guessing it wrong in the safe direction costs a
// failed request; guessing it wrong in the other direction writes the
// credential the route exists to add onto the wire in the clear.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

// wiretapTLSUpstream is an HTTPS server that also keeps the raw bytes of every
// connection, so a test can ask what actually went over the wire. Its
// certificate is issued for "localhost", the name the proxy will reach it by.
func wiretapTLSUpstream(t *testing.T) (addr string, roots *x509.CertPool, wire func() []byte) {
	t.Helper()

	leaf, pool := selfSignedFor(t, "localhost")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "upstream")
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	roots = pool

	// Stand a recording relay in front of it: everything the proxy writes is
	// copied out before being handed to the real TLS server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	var mu sync.Mutex
	var seen bytes.Buffer
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer client.Close()
				backend, err := net.Dial("tcp", srv.Listener.Addr().String())
				if err != nil {
					return
				}
				defer backend.Close()
				go io.Copy(client, backend)
				io.Copy(backend, io.TeeReader(client, &lockedWriter{mu: &mu, w: &seen}))
			}()
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return net.JoinHostPort("localhost", port), roots, func() []byte {
		mu.Lock()
		defer mu.Unlock()
		return append([]byte(nil), seen.Bytes()...)
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// The leak. A route that injects a credential, pointed at an HTTPS backend on
// any port but 443, used to be dialled in the clear: the request — credential
// and all — went out as plaintext to a server expecting a ClientHello, which
// dropped the connection, so the only sign of it was a 502 that reads like an
// ordinary upstream problem.
func TestCredentialIsNeverWrittenToTheUpstreamInTheClear(t *testing.T) {
	upstream, roots, wire := wiretapTLSUpstream(t)

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	p.SetTransportTLSConfig(&tls.Config{RootCAs: roots})
	if err := p.ForwardTo("api.corp", upstream,
		vtunnel.WithHeader("Authorization", "Bearer s3cret")); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	client := proxyClientFor(t, p.Addr().String(), ca)
	resp, err := client.Get("https://api.corp/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	sent := wire()
	if bytes.Contains(sent, []byte("s3cret")) {
		t.Fatalf("the credential went to the upstream in cleartext:\n%s", sent)
	}
	if len(sent) > 0 && sent[0] != 0x16 {
		t.Fatalf("first byte on the wire = %#x, want a TLS handshake record (0x16)", sent[0])
	}
	if resp.StatusCode != http.StatusOK || string(body) != "upstream" {
		t.Fatalf("response = %s %q, want the upstream's answer: an HTTPS backend on a "+
			"non-443 port should be reached over TLS, not refused", resp.Status, body)
	}
}

// Repeatedly. Nothing on this path remembered the failure, so every retry put
// another copy of the credential on the wire.
func TestCredentialLeakDoesNotRepeatAcrossRequests(t *testing.T) {
	upstream, roots, wire := wiretapTLSUpstream(t)

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	p.SetTransportTLSConfig(&tls.Config{RootCAs: roots})
	if err := p.ForwardTo("api.corp", upstream,
		vtunnel.WithHeader("Authorization", "Bearer s3cret")); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	client := proxyClientFor(t, p.Addr().String(), ca)
	for range 3 {
		if resp, err := client.Get("https://api.corp/x"); err == nil {
			io.ReadAll(resp.Body)
			resp.Body.Close()
		}
	}
	if n := bytes.Count(wire(), []byte("s3cret")); n != 0 {
		t.Fatalf("the credential appeared %d time(s) in cleartext on the wire", n)
	}
}

// A cleartext backend still works, and still gets its header — the common case
// must not be collateral damage.
func TestCleartextUpstreamStillGetsTheHeader(t *testing.T) {
	upstream, seen := authRecorder(t)

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("api.corp", upstream,
		vtunnel.WithHeader("Authorization", "Bearer injected")); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	resp, err := proxyClientFor(t, p.Addr().String(), ca).Get("https://api.corp/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	select {
	case got := <-seen:
		if got != "Bearer injected" {
			t.Fatalf("upstream saw Authorization=%q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the request never reached the upstream")
	}
}

// And saying so outright skips the question entirely.
func TestExplicitHTTPPrefixMeansCleartext(t *testing.T) {
	upstream, seen := authRecorder(t)

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("api.corp", "http://"+upstream,
		vtunnel.WithHeader("Authorization", "Bearer injected")); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	resp, err := proxyClientFor(t, p.Addr().String(), ca).Get("https://api.corp/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	select {
	case got := <-seen:
		if got != "Bearer injected" {
			t.Fatalf("upstream saw Authorization=%q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the request never reached the upstream")
	}
}

// proxyClientFor is a client that reaches everything through the proxy and
// trusts its CA.
func proxyClientFor(t *testing.T, proxyAddr string, ca tls.Certificate) *http.Client {
	t.Helper()
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(mustParseURL(t, "http://"+proxyAddr)),
			TLSClientConfig: &tls.Config{RootCAs: caPoolFor(t, ca)},
		},
	}
}

// selfSignedFor mints a certificate for one name, and the pool that trusts it.
func selfSignedFor(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}, pool
}
