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

// End-to-end through the whole chain: application -> sandbox egress proxy -> tunnel ->
// controlplane proxy -> backend. Asserts the security property the architecture
// exists for: an allowlisted domain is intercepted on the controlplane, and an
// unmapped one leaves the sandbox directly without ever meeting the MITM CA.
func TestEgressChainsMappedAndBypassesUnmapped(t *testing.T) {
	mapped := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "mapped:%s", r.Header.Get("Authorization"))
	}))
	defer mapped.Close()

	// A TLS backend the egress proxy must reach untouched. Its own certificate is the
	// evidence: if the request had gone through the controlplane proxy, the
	// client would see a cert signed by the MITM CA instead.
	direct := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "direct")
	}))
	direct.StartTLS()
	defer direct.Close()

	ts, server := startTunnelServer(t)
	defer ts.Close()

	egressAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := server.StartProxy(egressAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	ca := generateTestCA(t)
	client := vtunnel.NewClient(wsURL(ts), vtunnel.WithMitm(ca))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	if err := client.Proxy().ForwardTo("mapped.test", mapped.Listener.Addr().String(),
		vtunnel.WithHeader("Authorization", "Bearer chained")); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	httpClient := egressClient(t, egressAddr)

	// Mapped: chained to the controlplane, which injects the credential.
	resp, err := httpClient.Get("https://mapped.test/hello")
	if err != nil {
		t.Fatalf("mapped GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "mapped:Bearer chained" {
		t.Fatalf("mapped body = %q, want the injected credential", body)
	}

	// Unmapped: straight out of the sandbox, no interception.
	resp, err = httpClient.Get(direct.URL + "/hello")
	if err != nil {
		t.Fatalf("direct GET: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	peer := resp.TLS.PeerCertificates[0]
	resp.Body.Close()
	if string(body) != "direct" {
		t.Fatalf("direct body = %q, want direct", body)
	}

	caLeaf, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caLeaf)
	if _, err := peer.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Fatal("unmapped host was intercepted by the MITM CA; it must egress directly")
	}
}

// Forward and Unforward may be called repeatedly while connected: each call
// re-sends the full domain list and the egress proxy applies it wholesale.
//
// Routing is observed without relying on DNS: the forwarded authority is a real
// listener (the decoy). While mapped, requests reach the chained target; once
// unmapped, the very same request reaches the decoy directly.
func TestEgressRoutesUpdateAcrossMultipleForwards(t *testing.T) {
	chained := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "chained")
	}))
	defer chained.Close()

	decoy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "decoy")
	}))
	decoy.StartTLS()
	defer decoy.Close()

	bravo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "bravo")
	}))
	defer bravo.Close()

	ts, server := startTunnelServer(t)
	defer ts.Close()

	egressAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := server.StartProxy(egressAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	ca := generateTestCA(t)
	client := vtunnel.NewClient(wsURL(ts), vtunnel.WithMitm(ca))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	httpClient := egressClient(t, egressAddr)
	decoyAuthority := decoy.Listener.Addr().String()
	decoyURL := "https://" + decoyAuthority + "/"

	// Before any forward, the authority is not allowlisted: straight to the decoy.
	if got := getBody(t, httpClient, decoyURL); got != "decoy" {
		t.Fatalf("before forward = %q, want decoy", got)
	}

	// First listen request: the authority now chains to a different backend.
	if err := client.Proxy().ForwardTo(decoyAuthority, chained.Listener.Addr().String()); err != nil {
		t.Fatalf("Forward decoyAuthority: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if got := getBody(t, httpClient, decoyURL); got != "chained" {
		t.Fatalf("after forward = %q, want chained through the tunnel", got)
	}

	// Second listen request on the same tunnel port: both routes live.
	if err := client.Proxy().ForwardTo("bravo.test", bravo.Listener.Addr().String()); err != nil {
		t.Fatalf("Forward bravo: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if got := getBody(t, httpClient, "https://bravo.test/"); got != "bravo" {
		t.Fatalf("bravo = %q", got)
	}
	if got := getBody(t, httpClient, decoyURL); got != "chained" {
		t.Fatalf("first route after adding bravo = %q, want it still chained", got)
	}

	// Third: dropping one route must restore direct egress for it while the
	// other keeps working.
	client.Proxy().Remove(decoyAuthority)
	time.Sleep(150 * time.Millisecond)
	if got := getBody(t, httpClient, decoyURL); got != "decoy" {
		t.Fatalf("after Remove = %q, want decoy (direct egress restored)", got)
	}
	if got := getBody(t, httpClient, "https://bravo.test/"); got != "bravo" {
		t.Fatalf("bravo after dropping the other route = %q", got)
	}
}

// Wildcards resolve identically on both sides of the tunnel: the egress proxy
// allowlists by pattern and the controlplane proxy resolves the same pattern
// to a target.
func TestEgressWildcardThroughTunnel(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "wild:%s", r.Host)
	}))
	defer backend.Close()

	ts, server := startTunnelServer(t)
	defer ts.Close()

	egressAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := server.StartProxy(egressAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	ca := generateTestCA(t)
	client := vtunnel.NewClient(wsURL(ts), vtunnel.WithMitm(ca))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	if err := client.Proxy().ForwardTo("*.wild.test", backend.Listener.Addr().String()); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	httpClient := egressClient(t, egressAddr)
	for _, host := range []string{"a.wild.test", "deep.b.wild.test"} {
		if got := getBody(t, httpClient, "https://"+host+"/"); got != "wild:"+host {
			t.Fatalf("%s = %q", host, got)
		}
	}
}

// --- helpers ---

// egressClient is an HTTP client pointed at the sandbox egress proxy, standing in for
// an application with HTTPS_PROXY set.
func egressClient(t *testing.T, egressAddr string) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse("http://" + egressAddr)
	if err != nil {
		t.Fatalf("parse egress URL: %v", err)
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			// Each request must re-issue CONNECT, otherwise a pooled tunnel
			// keeps riding the route it was opened with. Real clients behave
			// the same way: a route change only takes effect on new connections.
			DisableKeepAlives: true,
		},
	}
}

func getBody(t *testing.T, c *http.Client, rawURL string) string {
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
