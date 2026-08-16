package vtunnel_test

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

// Forward and ForwardTo are the whole interception story: a forward with no
// target is piped through untouched, a forward with one is terminated and
// re-issued. These two tests pin that difference from the application's side.

// No target: the application must end up talking to the upstream's own
// certificate, not one minted by the CA. This is what makes pinned upstreams
// usable, and it needs no CA at all.
func TestForwardWithoutTargetKeepsTLSEndToEnd(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "upstream")
	}))
	upstream.StartTLS()
	defer upstream.Close()

	// The forwarded domain has to be an address the router can actually dial,
	// since "route it to itself" means exactly that.
	authority := upstream.Listener.Addr().String()

	routerAddr, ca, client, cleanup := startForwardFixture(t)
	defer cleanup()

	client.Proxy().Forward(authority)
	time.Sleep(150 * time.Millisecond)

	tlsConn := connectThroughRouter(t, routerAddr, authority, nil)
	defer tlsConn.Close()

	peer := tlsConn.ConnectionState().PeerCertificates[0]
	if signedBy(t, peer, ca) {
		t.Fatal("a forward with no target was intercepted; its TLS must reach the upstream untouched")
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

			routerAddr, _, client, cleanup := startForwardFixtureWithProxy(t, proxy)
			defer cleanup()

			// An explicit tls:// target, because the upstream is TLS on a port
			// that is not 443.
			client.Proxy().ForwardTo("alpn.test:443", "tls://"+upstream.Listener.Addr().String())
			time.Sleep(150 * time.Millisecond)

			tlsConn := connectThroughRouter(t, routerAddr, "alpn.test:443", []string{"h2", "http/1.1"})
			defer tlsConn.Close()

			if got := tlsConn.ConnectionState().NegotiatedProtocol; got != tc.want {
				t.Fatalf("application negotiated %q, want %q (upstream http2=%v)", got, tc.want, tc.upstreamHTTP2)
			}
		})
	}
}

// A wildcard Forward is fine: the host to dial comes from the request, not from
// the pattern, so "let everything under this suffix through untouched" is one
// call. A domain without a port covers both :80 and :443.
func TestForwardWildcardRegistersBothPorts(t *testing.T) {
	proxy := vtunnel.NewMITMProxy()
	proxy.Forward("*.wild.test")

	got := map[string]bool{}
	for _, r := range proxy.Routes() {
		got[r] = true
	}
	for _, want := range []string{"*.wild.test:80", "*.wild.test:443"} {
		if !got[want] {
			t.Fatalf("Routes() = %v, missing %s", proxy.Routes(), want)
		}
	}
}

// --- helpers ---

func startForwardFixture(t *testing.T) (routerAddr string, ca tls.Certificate, client *vtunnel.Client, cleanup func()) {
	t.Helper()
	ca = generateTestCA(t)
	routerAddr, _, client, cleanup = startForwardFixtureWithProxy(t, vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca)))
	return routerAddr, ca, client, cleanup
}

func startForwardFixtureWithProxy(t *testing.T, proxy *vtunnel.MITMProxy) (string, tls.Certificate, *vtunnel.Client, func()) {
	t.Helper()

	ts, server := startTunnelServer(t)
	routerAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := server.StartProxy(routerAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}

	client := vtunnel.NewClient(wsURL(ts), vtunnel.WithProxy(proxy))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	return routerAddr, tls.Certificate{}, client, func() {
		client.Close()
		server.CloseProxy()
		ts.Close()
	}
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

// connectThroughRouter issues CONNECT to the sandbox router and completes a TLS
// handshake inside the tunnel, standing in for an application with HTTPS_PROXY
// set. Passing nil for alpn offers no ALPN at all.
func connectThroughRouter(t *testing.T, routerAddr, authority string, alpn []string) *tls.Conn {
	t.Helper()

	conn, err := net.DialTimeout("tcp", routerAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial router: %v", err)
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
		t.Fatalf("TLS handshake through router: %v", err)
	}
	return tlsConn
}
