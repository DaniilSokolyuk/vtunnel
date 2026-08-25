package vtunnel

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// MITMExceptions takes the same domain syntax as a route, wildcards included,
// but the exclusion was looked up as an exact map key — so a wildcard exception
// never matched anything and silently did nothing.
func TestMITMExceptionsMatchWildcards(t *testing.T) {
	p := NewMITMProxy()
	p.MITMExceptions("*.pinned.corp")

	if blocked, _ := p.mitmBlocked("api.pinned.corp:443"); !blocked {
		t.Fatal("wildcard MITM exception did not match api.pinned.corp:443")
	}
	if blocked, _ := p.mitmBlocked("api.other.corp:443"); blocked {
		t.Fatal("wildcard MITM exception matched an unrelated domain")
	}
}

// A domain the caller named itself is excluded "whatever their route says".
// Learned exclusions deliberately do not apply to a route carrying headers —
// quietly dropping to a pipe would stop injecting a credential without saying
// so — but a configured one is the caller making that call knowingly.
func TestConfiguredExceptionAppliesToRouteWithHeaders(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "direct")
	}))
	upstream.StartTLS()
	defer upstream.Close()

	ca := generateProxyTestCA(t)
	p := NewMITMProxy(WithMitmCA(ca))
	if err := p.ForwardTo("pinned.corp", "tls://"+upstream.Listener.Addr().String(),
		WithHeader("Authorization", "Bearer secret")); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	p.MITMExceptions("pinned.corp")
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	// The upstream's own certificate proves the bytes were piped: had the proxy
	// intercepted, the client would have been offered a MITM-CA leaf instead.
	upstreamCert, _ := x509.ParseCertificate(upstream.TLS.Certificates[0].Certificate[0])
	roots := x509.NewCertPool()
	roots.AddCert(upstreamCert)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: p.Addr().String()}),
			TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com"},
		},
	}
	resp, err := client.Get("https://pinned.corp/")
	if err != nil {
		t.Fatalf("GET through configured exception: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "direct" {
		t.Fatalf("body = %q, want the piped upstream response", body)
	}
}

// Targets never cross the tunnel — except through an error string. A dial
// failure answered the sandbox with the controlplane-internal address it had
// just tried to reach.
func TestUpstreamErrorDoesNotLeakTargetAddress(t *testing.T) {
	// A port nothing listens on, so the dial fails and the error carries it.
	dead := fmt.Sprintf("127.0.0.1:%d", freeLocalPort(t))

	ca := generateProxyTestCA(t)
	p := NewMITMProxy(WithMitmCA(ca))
	if err := p.ForwardTo("api.corp", dead); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	client := proxyHTTPClient(p.Addr().String(), ca, false)
	resp, err := client.Get("https://api.corp/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if strings.Contains(string(body), dead) {
		t.Fatalf("error body %q leaks the internal target %q", body, dead)
	}
}

func freeLocalPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// The route — and the credential attached to it — is chosen by the CONNECT
// authority, but every request inside that connection carried its own Host.
// A sandbox could therefore aim the injected credential at any virtual host the
// upstream serves.
func TestForgedHostInsideInterceptedConnectionIsRefused(t *testing.T) {
	hosts := make(chan string, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case hosts <- r.Host:
		default:
		}
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	ca := generateProxyTestCA(t)
	p := NewMITMProxy(WithMitmCA(ca))
	if err := p.ForwardTo("api.corp", upstream.Listener.Addr().String(),
		WithHeader("Authorization", "Bearer secret")); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	leaf, _ := x509.ParseCertificate(ca.Certificate[0])
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	raw, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer raw.Close()
	fmt.Fprint(raw, "CONNECT api.corp:443 HTTP/1.1\r\nHost: api.corp:443\r\n\r\n")
	br := bufio.NewReader(raw)
	connectResp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	connectResp.Body.Close()
	if connectResp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %s", connectResp.Status)
	}

	tlsConn := tls.Client(newBufferedConn(raw, br), &tls.Config{RootCAs: roots, ServerName: "api.corp"})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	defer tlsConn.Close()

	fmt.Fprint(tlsConn, "GET / HTTP/1.1\r\nHost: victim.corp\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode == http.StatusOK {
		select {
		case got := <-hosts:
			t.Fatalf("upstream was reached with forged Host %q and the injected credential", got)
		default:
			t.Fatal("forged Host answered 200 without reaching the upstream")
		}
	}
}
