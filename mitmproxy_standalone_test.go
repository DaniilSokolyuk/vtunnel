package vtunnel_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

// MITMProxy depends on neither Server nor Client, so it can be used on its own
// as an intercepting forward proxy with no tunnel anywhere in sight. Start opens
// the listener itself; nothing else has to be wired up.
func TestMITMProxyStandalone(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "seen:%s", r.Header.Get("Authorization"))
	}))
	defer backend.Close()

	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "direct")
	}))
	defer direct.Close()

	// The whole setup: a CA, a proxy, one mapping.
	caPEM, err := vtunnel.GenerateCA("standalone test CA")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	ca, err := vtunnel.LoadCA(caPEM)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxy.Close()

	proxy.ForwardTo("api.test:443", backend.Listener.Addr().String(),
		vtunnel.WithHeader("Authorization", "Bearer injected"))

	// Start picked the port; Addr reports it.
	if proxy.Addr() == nil {
		t.Fatal("Addr is nil after Start")
	}
	client := proxyClient(t, proxy.Addr().String(), ca)

	// Mapped: intercepted, header injected.
	if got := readAll(t, client, "https://api.test/hello"); got != "seen:Bearer injected" {
		t.Fatalf("mapped = %q, want the injected credential", got)
	}

	// Unmapped: dialled straight through, no mapping needed.
	if got := readAll(t, client, direct.URL); got != "direct" {
		t.Fatalf("unmapped = %q, want direct", got)
	}
}

// Without a CA the same proxy still routes, it just never decrypts — so a
// mapped HTTPS domain is piped through to its target untouched.
func TestMITMProxyStandaloneWithoutCA(t *testing.T) {
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "backend")
	}))
	backend.StartTLS()
	defer backend.Close()

	proxy := vtunnel.NewMITMProxy()
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxy.Close()

	proxy.ForwardTo("plain.test:443", backend.Listener.Addr().String())

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(mustParseURL(t, "http://"+proxy.Addr().String())),
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}

	resp, err := client.Get("https://plain.test/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	// The certificate is the backend's own: nothing was terminated in between.
	backendCert, err := x509.ParseCertificate(backend.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse backend cert: %v", err)
	}
	if !resp.TLS.PeerCertificates[0].Equal(backendCert) {
		t.Fatal("a proxy with no CA must not terminate TLS")
	}
}

// --- helpers ---

func proxyClient(t *testing.T, proxyAddr string, ca tls.Certificate) *http.Client {
	t.Helper()

	caLeaf, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caLeaf)

	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(t, "http://"+proxyAddr)),
			// The generated leaf really does chain to the CA — no skipping verify.
			TLSClientConfig:   &tls.Config{RootCAs: roots},
			DisableKeepAlives: true,
		},
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", raw, err)
	}
	return u
}

func readAll(t *testing.T, c *http.Client, rawURL string) string {
	t.Helper()
	resp, err := c.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", rawURL, err)
	}
	return string(body)
}
