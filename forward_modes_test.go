package vtunnel_test

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

// Forward and ForwardTo differ in where the target comes from, and in nothing
// else: whether the connection is decrypted is the CA's business and the
// exceptions', not the route's. These tests pin that from the application's
// side, which is the only side that can tell.

// A CA is configured, so a forward with no target is intercepted like any
// other route: what reaches the application is a leaf this proxy minted, and
// the proxy holds the upstream's certificate rather than passing it on.
func TestForwardWithoutTargetIsInterceptedWhenThereIsACA(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "upstream")
	}))
	upstream.StartTLS()
	defer upstream.Close()

	// The forwarded domain has to be an address the egress proxy can actually dial,
	// since "go to the host you asked for" means exactly that.
	authority := upstream.Listener.Addr().String()

	ca := generateTestCA(t)
	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	// Terminating means this proxy is now the one verifying the upstream, which
	// is the whole cost of the change: a privately signed upstream has to be
	// trusted here rather than by the application.
	proxy.SetTransportTLSConfig(&tls.Config{RootCAs: poolWith(t, upstream.Certificate())})

	egressAddr, _, client, cleanup := startForwardFixtureWithProxy(t, proxy)
	defer cleanup()

	client.Proxy().Forward(authority)
	time.Sleep(150 * time.Millisecond)

	tlsConn := connectThroughEgress(t, egressAddr, authority, nil)
	defer tlsConn.Close()

	if peer := tlsConn.ConnectionState().PeerCertificates[0]; !signedBy(t, peer, ca) {
		t.Fatal("a forward with no target was piped; with a CA it must be intercepted")
	}
	if got := getOver(t, tlsConn, authority); got != "upstream" {
		t.Fatalf("got %q, want the upstream's response through the intercepted connection", got)
	}
}

// No CA: there is nothing to terminate with, so the application ends up
// talking to the upstream's own certificate.
func TestForwardWithoutTargetKeepsTLSEndToEndWithoutACA(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "upstream")
	}))
	upstream.StartTLS()
	defer upstream.Close()

	authority := upstream.Listener.Addr().String()

	egressAddr, _, client, cleanup := startForwardFixtureWithProxy(t, vtunnel.NewMITMProxy())
	defer cleanup()

	client.Proxy().Forward(authority)
	time.Sleep(150 * time.Millisecond)

	tlsConn := connectThroughEgress(t, egressAddr, authority, nil)
	defer tlsConn.Close()

	peer := tlsConn.ConnectionState().PeerCertificates[0]
	if !peer.Equal(upstream.Certificate()) {
		t.Fatalf("the application was handed %v, want the upstream's own certificate", peer.Subject)
	}
}

// And an upstream that must not be intercepted says so. This is the one way
// out of interception now, which is why it has to work for a route whose
// target is the host the client asked for — there is no configured address for
// the pipe to aim at, only the authority.
func TestMITMExceptionPipesAForwardWithNoTarget(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "upstream")
	}))
	upstream.StartTLS()
	defer upstream.Close()

	authority := upstream.Listener.Addr().String()

	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(generateTestCA(t)))
	proxy.MITMExceptions(authority)

	egressAddr, _, client, cleanup := startForwardFixtureWithProxy(t, proxy)
	defer cleanup()

	client.Proxy().Forward(authority)
	time.Sleep(150 * time.Millisecond)

	tlsConn := connectThroughEgress(t, egressAddr, authority, nil)
	defer tlsConn.Close()

	peer := tlsConn.ConnectionState().PeerCertificates[0]
	if !peer.Equal(upstream.Certificate()) {
		t.Fatalf("the application was handed %v, want the upstream's own certificate", peer.Subject)
	}
}

// With a target, the proxy terminates TLS — and because it dials the upstream
// before finishing the client handshake, the protocol the application gets is
// the one the upstream actually agreed to, not a blind guess.
func TestForwardToMirrorsUpstreamALPN(t *testing.T) {
	for _, tc := range []struct {
		name          string
		upstreamHTTP2 bool
		want          string
	}{
		{name: "http1 upstream is not advertised as h2", want: "http/1.1"},
		{name: "h2 upstream is advertised as h2", upstreamHTTP2: true, want: "h2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, "upstream")
			}))
			upstream.EnableHTTP2 = tc.upstreamHTTP2
			upstream.StartTLS()
			defer upstream.Close()

			upstreamCert, err := x509.ParseCertificate(upstream.TLS.Certificates[0].Certificate[0])
			if err != nil {
				t.Fatalf("parse upstream cert: %v", err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(upstreamCert)

			proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(generateTestCA(t)))
			proxy.SetTransportTLSConfig(&tls.Config{RootCAs: roots})

			egressAddr, _, client, cleanup := startForwardFixtureWithProxy(t, proxy)
			defer cleanup()

			// An explicit tls:// target, because the upstream is TLS on a port
			// that is not 443.
			client.Proxy().ForwardTo("alpn.test:443", "tls://"+upstream.Listener.Addr().String())
			time.Sleep(150 * time.Millisecond)

			tlsConn := connectThroughEgress(t, egressAddr, "alpn.test:443", []string{"h2", "http/1.1"})
			defer tlsConn.Close()

			if got := tlsConn.ConnectionState().NegotiatedProtocol; got != tc.want {
				t.Fatalf("application negotiated %q, want %q (upstream http2=%v)", got, tc.want, tc.upstreamHTTP2)
			}
		})
	}
}

// A forward with no target carries a credential too. It re-issues the request
// to the host that was asked for, which is a request like any other, so there
// has never been anything for a header to be missing from — and saying so meant
// naming the host twice and a port with it.
func TestTargetlessForwardInjectsHeadersOnAnyPort(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, "upstream")
	}))
	upstream.StartTLS()
	defer upstream.Close()

	// "go to the host you asked for" means the authority has to be dialable.
	authority := upstream.Listener.Addr().String()
	host, port, _ := net.SplitHostPort(authority)
	if port == "443" {
		t.Skip("httptest picked 443, which cannot show the difference")
	}

	ca := generateTestCA(t)
	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	proxy.SetTransportTLSConfig(&tls.Config{RootCAs: poolWith(t, upstream.Certificate())})

	egressAddr, _, client, cleanup := startForwardFixtureWithProxy(t, proxy)
	defer cleanup()

	// The host alone: every port of it, to itself, with the credential.
	if err := client.Proxy().Forward(host,
		vtunnel.WithHeader("Authorization", "Bearer sk-ant-xxx")); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	tlsConn := connectThroughEgress(t, egressAddr, authority, nil)
	defer tlsConn.Close()

	if peer := tlsConn.ConnectionState().PeerCertificates[0]; !signedBy(t, peer, ca) {
		t.Fatalf("%s was piped, so the credential was never injected", authority)
	}
	if got := getOver(t, tlsConn, authority); got != "upstream" {
		t.Fatalf("got %q, want the upstream's response", got)
	}
	if gotAuth != "Bearer sk-ant-xxx" {
		t.Fatalf("upstream saw Authorization %q, want the injected credential", gotAuth)
	}
}

// A credential needs interception, so a forward carrying one is refused where it
// is declared on a proxy that has no CA — the same rule ForwardTo follows, and
// for the same reason: a route that answered normally and simply never added the
// header is a failure with nothing to see.
func TestTargetlessForwardWithHeadersNeedsACA(t *testing.T) {
	proxy := vtunnel.NewMITMProxy()
	if err := proxy.Forward("gitlab.corp", vtunnel.WithHeader("Authorization", "Bearer s3cret")); err == nil {
		t.Fatal("a forward carrying a header was accepted on a proxy with no CA")
	}
	if err := proxy.Forward("gitlab.corp"); err != nil {
		t.Fatalf("a forward carrying nothing was refused: %v", err)
	}
}

// The same over a target that names a host and no port, which is the longer way
// of saying the test above.
func TestPortlessRouteAndTargetInterceptOnAnyPort(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, "upstream")
	}))
	upstream.StartTLS()
	defer upstream.Close()

	// Whatever port httptest picked, and it is not 443 — which is the point.
	upstreamHost, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	if upstreamPort == "443" {
		t.Skip("httptest picked 443, which cannot show the difference")
	}

	ca := generateTestCA(t)
	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	proxy.SetTransportTLSConfig(&tls.Config{RootCAs: poolWith(t, upstream.Certificate())})

	egressAddr, _, client, cleanup := startForwardFixtureWithProxy(t, proxy)
	defer cleanup()

	// Neither side names a port and no scheme is stated: the route covers every
	// port of gitlab.corp, the target is reached on whichever one the
	// application asked for, and how to speak to it is followed from the client.
	// The port used to be what said TLS, so without this the upstream would be
	// handed a cleartext request and answer with an error page.
	if err := client.Proxy().ForwardTo("gitlab.corp", upstreamHost,
		vtunnel.WithHeader("Authorization", "Bearer sk-ant-xxx")); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	authority := net.JoinHostPort("gitlab.corp", upstreamPort)
	tlsConn := connectThroughEgress(t, egressAddr, authority, nil)
	defer tlsConn.Close()

	if peer := tlsConn.ConnectionState().PeerCertificates[0]; !signedBy(t, peer, ca) {
		t.Fatalf("gitlab.corp:%s was piped, so the credential was never injected", upstreamPort)
	}
	if got := getOver(t, tlsConn, authority); got != "upstream" {
		t.Fatalf("got %q, want the upstream's response", got)
	}
	if gotAuth != "Bearer sk-ant-xxx" {
		t.Fatalf("upstream saw Authorization %q, want the injected credential", gotAuth)
	}
}

// Following the client is what a route says nothing about how is owed, and no
// more than that: a stated scheme still decides, and so does a stated SNI.
func TestPortlessTargetDoesNotOverrideAStatedScheme(t *testing.T) {
	var sawTLS bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawTLS = r.TLS != nil
		fmt.Fprint(w, "cleartext upstream")
	}))
	defer upstream.Close()
	upstreamHost, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	ca := generateTestCA(t)
	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	egressAddr, _, client, cleanup := startForwardFixtureWithProxy(t, proxy)
	defer cleanup()

	// "http://" says cleartext outright, port or no port. The client speaks TLS
	// to the proxy and the upstream leg must not follow it.
	if err := client.Proxy().ForwardTo("legacy.corp", "http://"+upstreamHost); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	authority := net.JoinHostPort("legacy.corp", upstreamPort)
	tlsConn := connectThroughEgress(t, egressAddr, authority, nil)
	defer tlsConn.Close()

	if got := getOver(t, tlsConn, authority); got != "cleartext upstream" {
		t.Fatalf("got %q, want the cleartext upstream's response", got)
	}
	if sawTLS {
		t.Fatal("an http:// target was reached over TLS; a stated scheme decides")
	}
}

// WithTarget and ForwardTo are the same route said two ways, and a caller
// building options up must not get a different answer from one writing the
// target out.
func TestWithTargetAndForwardToAgree(t *testing.T) {
	ca := generateTestCA(t)
	viaOption := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	viaMethod := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))

	for _, target := range []string{
		"localhost:8081", "gw.internal", "tls://api.corp", "tls://api.corp:8443",
		"h2c://api.internal:13002", "http://legacy.corp",
	} {
		optErr := viaOption.Forward("api.test", vtunnel.WithTarget(target),
			vtunnel.WithHeader("X-Env", "preview"))
		methodErr := viaMethod.ForwardTo("api.test", target,
			vtunnel.WithHeader("X-Env", "preview"))
		if (optErr == nil) != (methodErr == nil) {
			t.Fatalf("target %q: WithTarget err = %v, ForwardTo err = %v", target, optErr, methodErr)
		}
	}

	// And the option slice the caller handed over is not written into.
	opts := make([]vtunnel.ForwardOption, 1, 4)
	opts[0] = vtunnel.WithHeader("X-Env", "preview")
	if err := viaMethod.ForwardTo("api.test", "localhost:8081", opts...); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if len(opts) != 1 {
		t.Fatalf("the caller's options grew to %d entries", len(opts))
	}
	if err := viaMethod.Forward("other.test", opts...); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if got := viaMethod.Routes(); len(got) != 2 {
		t.Fatalf("Routes() = %v; the appended target leaked into the caller's slice", got)
	}
}

// An empty target is still refused where a target is what the method is for.
func TestForwardToRefusesAnEmptyTarget(t *testing.T) {
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(generateTestCA(t)))
	if err := p.ForwardTo("api.test", ""); err == nil {
		t.Fatal("ForwardTo with an empty target was accepted")
	}
	if err := p.Forward("api.test"); err != nil {
		t.Fatalf("Forward with no target was refused: %v", err)
	}
}

// A wildcard Forward is fine: the host to dial comes from the request, not from
// the pattern, so "let everything under this suffix through untouched" is one
// call. It is registered as written — a domain without a port covers every
// port, and the sandbox is told the same one key rather than an expansion of it.
func TestForwardWildcardRegistersOneKeyForEveryPort(t *testing.T) {
	proxy := vtunnel.NewMITMProxy()
	proxy.Forward("*.wild.test")

	if got := proxy.Routes(); len(got) != 1 || got[0] != "*.wild.test" {
		t.Fatalf("Routes() = %v, want exactly [*.wild.test]", got)
	}
}

// --- helpers ---

func startForwardFixture(t *testing.T) (egressAddr string, ca tls.Certificate, client *vtunnel.Client, cleanup func()) {
	t.Helper()
	ca = generateTestCA(t)
	egressAddr, _, client, cleanup = startForwardFixtureWithProxy(t, vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca)))
	return egressAddr, ca, client, cleanup
}

func startForwardFixtureWithProxy(t *testing.T, proxy *vtunnel.MITMProxy) (string, tls.Certificate, *vtunnel.Client, func()) {
	t.Helper()

	ts, server := startTunnelServer(t)
	egressAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := server.StartProxy(egressAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}

	client := vtunnel.NewClient(wsURL(ts), vtunnel.WithProxy(proxy))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	return egressAddr, tls.Certificate{}, client, func() {
		client.Close()
		server.CloseProxy()
		ts.Close()
	}
}

// poolWith is a root pool holding one certificate, for an upstream this proxy
// now has to verify itself.
func poolWith(t *testing.T, cert *x509.Certificate) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}

// getOver issues one GET over an already-established TLS connection and returns
// the body, so a test can check that the intercepted connection carries traffic
// and not just a certificate.
func getOver(t *testing.T, conn net.Conn, authority string) string {
	t.Helper()

	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", authority); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}

// signedBy reports whether cert chains to the given CA.
func signedBy(t *testing.T, cert *x509.Certificate, ca tls.Certificate) bool {
	t.Helper()
	caLeaf, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caLeaf)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err == nil
}

// connectThroughEgress issues CONNECT to the sandbox egress proxy and completes a TLS
// handshake inside the tunnel, standing in for an application with HTTPS_PROXY
// set. Passing nil for alpn offers no ALPN at all.
func connectThroughEgress(t *testing.T, egressAddr, authority string, alpn []string) *tls.Conn {
	t.Helper()

	conn, err := net.DialTimeout("tcp", egressAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial the egress proxy: %v", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT failed: %s", resp.Status)
	}

	host, _, _ := net.SplitHostPort(authority)
	tlsConn := tls.Client(newBufConn(conn, br), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		NextProtos:         alpn,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake through the egress proxy: %v", err)
	}
	return tlsConn
}
