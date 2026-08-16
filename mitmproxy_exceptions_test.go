package vtunnel

// Interception can be impossible rather than merely broken: a client that pins
// certificates will refuse the generated leaf every single time, and an upstream
// demanding mutual TLS will refuse the proxy every single time. Retrying either
// on every request turns one misconfiguration into a permanently dead domain.
//
// These tests cover learning that, and — just as important — the cases where the
// proxy must NOT quietly degrade.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// A pinned client refuses the generated leaf. The first request is lost either
// way; the point is that the next one gets through instead of failing the same
// way forever.
func TestMITMFallsBackAfterClientRefusesLeaf(t *testing.T) {
	upstreamCA := testCA(t, "upstream CA")
	upstreamAddr := tlsEchoServer(t, "pinned.test", upstreamCA, "reached-upstream")

	proxy, proxyAddr := exceptionsProxy(t)
	proxy.ForwardTo("pinned.test:443", upstreamAddr)

	// Trusts the real upstream's CA and nothing else — so the proxy's leaf is
	// rejected, exactly as a pinning client would.
	client := pinnedClient(t, proxyAddr, upstreamCA)

	if _, err := client.Get("https://pinned.test/"); err == nil {
		t.Fatal("the first request succeeded; the client was supposed to reject the generated leaf")
	}
	// The client sees its own handshake fail before the proxy has finished
	// recording why, so this is a wait rather than an immediate read.
	waitBlocked(t, proxy, "pinned.test:443")

	// Second time around the proxy pipes, and the client completes its own
	// handshake with the upstream it actually trusts.
	resp, err := client.Get("https://pinned.test/")
	if err != nil {
		t.Fatalf("the request after the fallback still failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "reached-upstream" {
		t.Fatalf("body = %q, want the upstream's own response", body)
	}
}

// A route carrying headers must keep failing. Falling back would leave the
// request working while the credential silently stopped being attached, which
// hides the problem instead of reporting it.
func TestMITMDoesNotFallBackWhenHeadersAreConfigured(t *testing.T) {
	upstreamCA := testCA(t, "upstream CA")
	upstreamAddr := tlsEchoServer(t, "pinned.test", upstreamCA, "reached-upstream")

	proxy, proxyAddr := exceptionsProxy(t)
	proxy.ForwardTo("pinned.test:443", upstreamAddr, WithHeader("Authorization", "Bearer secret"))

	client := pinnedClient(t, proxyAddr, upstreamCA)

	if _, err := client.Get("https://pinned.test/"); err == nil {
		t.Fatal("first request succeeded unexpectedly")
	}
	if blocked, _ := proxy.mitmBlocked("pinned.test:443"); blocked {
		t.Fatal("a route with injected headers was excluded from interception; " +
			"it would keep working while the credential quietly went missing")
	}
	if _, err := client.Get("https://pinned.test/"); err == nil {
		t.Fatal("second request succeeded; the failure must stay visible")
	}
}

// A handler route has no address to pipe to, so there is nothing to fall back
// to even in principle.
func TestMITMDoesNotFallBackForHandlerRoute(t *testing.T) {
	proxy, proxyAddr := exceptionsProxy(t)
	proxy.Handle("pinned.test:443", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "in-process")
	}))

	client := pinnedClient(t, proxyAddr, testCA(t, "unrelated CA"))
	if _, err := client.Get("https://pinned.test/"); err == nil {
		t.Fatal("first request succeeded unexpectedly")
	}
	if blocked, _ := proxy.mitmBlocked("pinned.test:443"); blocked {
		t.Fatal("a handler route was excluded from interception, but it has no target to pipe to")
	}
}

// Stating the exception up front skips the doomed handshake entirely, so not
// even the first request is lost.
func TestMITMExceptionsSkipInterceptionFromTheStart(t *testing.T) {
	upstreamCA := testCA(t, "upstream CA")
	upstreamAddr := tlsEchoServer(t, "pinned.test", upstreamCA, "reached-upstream")

	proxy, proxyAddr := exceptionsProxy(t)
	proxy.ForwardTo("pinned.test:443", upstreamAddr)
	proxy.MITMExceptions("pinned.test")

	client := pinnedClient(t, proxyAddr, upstreamCA)
	resp, err := client.Get("https://pinned.test/")
	if err != nil {
		t.Fatalf("first request failed even though the domain is excepted: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "reached-upstream" {
		t.Fatalf("body = %q, want the upstream's own response", body)
	}

	// Configured exceptions carry no expiry and must not be swept away.
	proxy.noMITMMu.Lock()
	proxy.sweepNoMITMLocked(time.Now().Add(100 * noMITMTTL))
	proxy.noMITMMu.Unlock()
	if blocked, _ := proxy.mitmBlocked("pinned.test:443"); !blocked {
		t.Fatal("a configured exception expired; only learned ones should")
	}
}

// A learned exclusion has to lapse, or installing the CA in the client would
// need a restart to take effect.
func TestMITMLearnedExclusionExpires(t *testing.T) {
	proxy := NewMITMProxy()

	proxy.noMITMMu.Lock()
	proxy.noMITM = map[string]time.Time{"stale.test:443": time.Now().Add(-time.Minute)}
	proxy.noMITMMu.Unlock()

	if blocked, _ := proxy.mitmBlocked("stale.test:443"); blocked {
		t.Fatal("an expired exclusion is still in force")
	}

	proxy.noMITMMu.RLock()
	_, still := proxy.noMITM["stale.test:443"]
	proxy.noMITMMu.RUnlock()
	if still {
		t.Fatal("the expired entry was not dropped, so the map grows without bound")
	}
}

// An upstream that merely offers mutual TLS accepts an empty certificate, which
// is what crypto/tls sends by default. gomitmproxy makes this case detectable by
// failing the hook outright, which also breaks these upstreams — so the proxy
// observes the request instead, and this pins that down.
func TestOptionalClientCertUpstreamStillIntercepts(t *testing.T) {
	upstreamCA := testCA(t, "upstream CA")
	upstreamAddr := tlsEchoServerAuth(t, "optional.test", upstreamCA, "reached-upstream", tls.RequestClientCert)

	proxy, proxyAddr := exceptionsProxy(t)
	proxy.SetTransportTLSConfig(&tls.Config{RootCAs: poolFor(t, upstreamCA)})
	// WithSNI, because the target is an address while the upstream certificate
	// is issued for the hostname.
	proxy.ForwardTo("optional.test:443", "tls://"+upstreamAddr, WithSNI("optional.test"))

	client := pinnedClient(t, proxyAddr, proxy.mitmCAForTest())
	resp, err := client.Get("https://optional.test/")
	if err != nil {
		t.Fatalf("interception failed against an upstream that only offers mutual TLS: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "reached-upstream" {
		t.Fatalf("body = %q", body)
	}
	if blocked, _ := proxy.mitmBlocked("optional.test:443"); blocked {
		t.Fatal("an optional client-certificate request was treated as a refusal")
	}
}

// An upstream that requires a client certificate cannot be intercepted.
//
// Under TLS 1.3 the client certificate travels after the handshake is otherwise
// complete, so the proxy's HandshakeContext returns success and the rejection
// only lands on the first exchange. Detection therefore cannot live in
// dialTLSUpstream alone, and this drives the whole path to prove it.
func TestRequiredClientCertUpstreamStopsInterception(t *testing.T) {
	upstreamCA := testCA(t, "upstream CA")
	upstreamAddr := tlsEchoServerAuth(t, "mtls.test", upstreamCA, "unreachable", tls.RequireAnyClientCert)

	proxy, proxyAddr := exceptionsProxy(t)
	proxy.SetTransportTLSConfig(&tls.Config{RootCAs: poolFor(t, upstreamCA)})
	proxy.ForwardTo("mtls.test:443", "tls://"+upstreamAddr, WithSNI("mtls.test"))

	client := pinnedClient(t, proxyAddr, proxy.mitmCAForTest())
	resp, err := client.Get("https://mtls.test/")
	if err == nil {
		if resp.StatusCode != http.StatusBadGateway {
			resp.Body.Close()
			t.Fatalf("status = %d, want 502: the upstream requires a client certificate", resp.StatusCode)
		}
		resp.Body.Close()
	}

	waitBlocked(t, proxy, "mtls.test:443")
}

// The handshake-time half of the same detection, which is what TLS 1.2 and any
// upstream that rejects during the handshake take.
func TestClientCertRequestIsWrappedOnHandshakeFailure(t *testing.T) {
	upstreamCA := testCA(t, "upstream CA")
	upstreamAddr := tlsEchoServerAuthMaxTLS12(t, "mtls12.test", upstreamCA, tls.RequireAnyClientCert)

	proxy, _ := exceptionsProxy(t)
	proxy.SetTransportTLSConfig(&tls.Config{RootCAs: poolFor(t, upstreamCA)})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := proxy.dialTLSUpstream(ctx, upstreamAddr, "mtls12.test", []string{"http/1.1"})
	if err == nil {
		t.Fatal("the handshake succeeded without a client certificate")
	}
	if !errors.Is(err, errClientCertRequested) {
		t.Fatalf("err = %v, want it to report the client-certificate request", err)
	}
	if !mitmRefused(err) {
		t.Fatal("a required client certificate was not classified as a refusal")
	}
}

// The classifier decides how long traffic goes un-intercepted, so being wrong in
// the permissive direction is the expensive mistake. Only causes that are
// properties of the peer may count.
func TestMITMRefusedClassification(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "no error", err: nil, want: false},
		{name: "connection refused", err: errors.New("dial tcp 127.0.0.1:1: connect: connection refused"), want: false},
		{name: "closed", err: net.ErrClosed, want: false},
		{name: "generic handshake failure", err: errors.New("remote error: tls: handshake failure"), want: false},
		{name: "client rejected our leaf", err: errors.New("remote error: tls: bad certificate"), want: true},
		{name: "client does not trust our CA", err: errors.New("remote error: tls: unknown certificate authority"), want: true},
		{name: "upstream wants a client cert", err: fmt.Errorf("%w: %w", errClientCertRequested, errors.New("boom")), want: true},
		{name: "upstream CA unknown", err: fmt.Errorf("dial: %w", x509.UnknownAuthorityError{}), want: true},
		{name: "upstream cert name mismatch", err: fmt.Errorf("dial: %w", x509.HostnameError{Host: "x"}), want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mitmRefused(tc.err); got != tc.want {
				t.Fatalf("mitmRefused(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// --- helpers ---

func exceptionsProxy(t *testing.T) (*MITMProxy, string) {
	t.Helper()
	blob, err := GenerateCA("exceptions test CA")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	ca, err := LoadCA(blob)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	proxy := NewMITMProxy(WithMitmCA(ca))
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(proxy.Close)
	return proxy, proxy.Addr().String()
}

func (p *MITMProxy) mitmCAForTest() tls.Certificate { return *p.mitmCA }

func testCA(t *testing.T, name string) tls.Certificate {
	t.Helper()
	blob, err := GenerateCA(name)
	if err != nil {
		t.Fatalf("GenerateCA(%s): %v", name, err)
	}
	ca, err := LoadCA(blob)
	if err != nil {
		t.Fatalf("LoadCA(%s): %v", name, err)
	}
	return ca
}

func poolFor(t *testing.T, ca tls.Certificate) *x509.CertPool {
	t.Helper()
	leaf, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return pool
}

// waitBlocked waits for the proxy to record that a domain cannot be
// intercepted. The client learns its handshake failed before the proxy has
// finished writing that down, so polling is the honest way to observe it.
func waitBlocked(t *testing.T, p *MITMProxy, authority string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if blocked, _ := p.mitmBlocked(authority); blocked {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s was never excluded from interception, so every later request would fail the same way", authority)
}

func tlsEchoServer(t *testing.T, hostname string, ca tls.Certificate, body string) string {
	t.Helper()
	return tlsEchoServerAuth(t, hostname, ca, body, tls.NoClientCert)
}

// tlsEchoServerAuthMaxTLS12 pins the upstream to TLS 1.2, where a missing client
// certificate is refused during the handshake rather than after it.
func tlsEchoServerAuthMaxTLS12(t *testing.T, hostname string, ca tls.Certificate, auth tls.ClientAuthType) string {
	t.Helper()
	return tlsEchoServerConfig(t, hostname, ca, "unreachable", auth, tls.VersionTLS12)
}

// tlsEchoServerAuth serves body over TLS with a certificate for hostname signed
// by ca, so a client trusting ca can verify it by name.
func tlsEchoServerAuth(t *testing.T, hostname string, ca tls.Certificate, body string, auth tls.ClientAuthType) string {
	t.Helper()
	return tlsEchoServerConfig(t, hostname, ca, body, auth, 0)
}

func tlsEchoServerConfig(t *testing.T, hostname string, ca tls.Certificate, body string, auth tls.ClientAuthType, maxVersion uint16) string {
	t.Helper()

	cache, err := newCertCache(ca)
	if err != nil {
		t.Fatalf("newCertCache: %v", err)
	}
	leaf, _, err := cache.signHost(hostname, keyECDSA, time.Now())
	if err != nil {
		t.Fatalf("signHost(%s): %v", hostname, err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, body)
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*leaf},
			ClientAuth:   auth,
			NextProtos:   []string{"http/1.1"},
			MaxVersion:   maxVersion,
		},
	}
	go srv.Serve(tls.NewListener(ln, srv.TLSConfig))
	t.Cleanup(func() { srv.Close() })

	return ln.Addr().String()
}

// pinnedClient trusts exactly one CA, so anything signed by another is rejected
// the way a certificate-pinning application would reject it.
func pinnedClient(t *testing.T, proxyAddr string, trusted tls.Certificate) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			TLSClientConfig:   &tls.Config{RootCAs: poolFor(t, trusted)},
			DisableKeepAlives: true,
		},
	}
}
