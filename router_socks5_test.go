package vtunnel_test

// SOCKS5 into the sandbox router.
//
// The point of it is the traffic that never had a way in: psql, redis-cli, ssh,
// anything that does not read HTTPS_PROXY. Such a client egressed from the
// sandbox directly, past the allowlist and past the credential the controlplane
// would have injected — not because that was decided, but because nothing
// asked it where it was going.
//
// The rule the tests below exist to hold: what the sandbox may say is a name;
// what the controlplane does with that name comes from its own configuration.
// So a domain nobody forwarded must never reach the tunnel, and a route for one
// port must never cover another.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/vivid-money/vtunnel"
)

// tcpEcho answers every connection with "who: " plus whatever it was sent,
// once the sender is done writing. Reading to EOF makes it a half-close test
// as well as a routing one.
func tcpEcho(t *testing.T, who string) (addr string, hits *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	hits = &atomic.Int32{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			go func() {
				defer conn.Close()
				req, _ := io.ReadAll(conn)
				fmt.Fprintf(conn, "%s: %s", who, req)
			}()
		}
	}()
	return ln.Addr().String(), hits
}

// sandbox brings up a server with its router, a client with a MITM CA, and the
// tunnel between them — the whole chain an application in a sandbox sees.
func sandbox(t *testing.T) (routerAddr string, client *vtunnel.Client) {
	t.Helper()

	ts, server := startTunnelServer(t)
	t.Cleanup(ts.Close)

	routerAddr = fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := server.StartProxy(routerAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	t.Cleanup(server.CloseProxy)

	client = vtunnel.NewClient(wsURL(ts), vtunnel.WithMitm(generateTestCA(t)))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return routerAddr, client
}

// socksDial dials target through the router's SOCKS5 front end, the way a
// client with ALL_PROXY=socks5h://… does: the name travels, unresolved.
func socksDial(t *testing.T, routerAddr, target string) net.Conn {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", routerAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("socks5 dialer: %v", err)
	}
	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		t.Fatalf("socks5 dial %s: %v", target, err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

func ask(t *testing.T, conn net.Conn, what string) string {
	t.Helper()
	if _, err := conn.Write([]byte(what)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
	answer, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(answer)
}

// A forwarded domain on a non-HTTP port reaches the controlplane's target
// through the tunnel. This is the whole feature: postgres, redis, ssh.
func TestSocks5ForwardedPortGoesThroughTheTunnel(t *testing.T) {
	controlplaneOnly, _ := tcpEcho(t, "controlplane")
	routerAddr, client := sandbox(t)

	// The name the application uses, and the address only the controlplane
	// knows. Nothing but the name crosses the tunnel.
	if err := client.Proxy().ForwardTo("db.corp:5432", controlplaneOnly); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	conn := socksDial(t, routerAddr, "db.corp:5432")
	if got := ask(t, conn, "SELECT 1"); got != "controlplane: SELECT 1" {
		t.Fatalf("answer = %q, want the controlplane's target", got)
	}
}

// The security property. A domain nobody forwarded must egress from the sandbox
// directly — never through the tunnel, where it would be dialled from inside
// the controlplane's network.
func TestSocks5UnroutedDomainNeverEntersTheTunnel(t *testing.T) {
	tunnelSide, tunnelHits := tcpEcho(t, "controlplane")
	direct, _ := tcpEcho(t, "direct")

	routerAddr, client := sandbox(t)
	// One route exists, for something else entirely.
	if err := client.Proxy().ForwardTo("db.corp:5432", tunnelSide); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	before := tunnelHits.Load()

	// By name, because that is what the rule is about: an unrouted name is
	// ordinary sandbox egress. (An unrouted address is refused outright — see
	// TestSocks5UnroutedIPLiteralIsRefused.)
	_, directPort, _ := net.SplitHostPort(direct)
	conn := socksDial(t, routerAddr, net.JoinHostPort("localhost", directPort))
	if got := ask(t, conn, "hello"); !strings.HasPrefix(got, "direct:") {
		t.Fatalf("answer = %q, want the direct target", got)
	}
	if now := tunnelHits.Load(); now != before {
		t.Fatalf("the controlplane's target was dialled %d time(s) for an unrouted address: "+
			"anything in the sandbox can reach the controlplane's network through the tunnel",
			now-before)
	}
}

// A route is a host and a port together. A wildcard for :5432 must not hand out
// :22 on the same domain — that is the difference between forwarding a database
// and forwarding ssh.
func TestSocks5RouteDoesNotLeakToOtherPorts(t *testing.T) {
	tunnelSide, tunnelHits := tcpEcho(t, "controlplane")
	routerAddr, client := sandbox(t)

	if err := client.Proxy().ForwardTo("*.corp:5432", tunnelSide); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	// Nothing listens on this port anywhere; what matters is where the router
	// tried to go, not whether it arrived.
	before := tunnelHits.Load()
	dialer, err := proxy.SOCKS5("tcp", routerAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("socks5 dialer: %v", err)
	}
	if conn, err := dialer.Dial("tcp", "db.corp:22"); err == nil {
		conn.Close()
	}

	if now := tunnelHits.Load(); now != before {
		t.Fatal("a route for :5432 carried :22 into the tunnel")
	}
}

// An address that is in no route is refused outright, rather than dialled.
//
// Policy here is written in names, and an address cannot be matched against
// one: a client configured as socks5:// resolves first and sends the result, so
// its traffic would slip past the allowlist and the credential without a word.
// Refusing turns that into an error the operator sees the first time, and
// leaves the escape hatch where it belongs — forward the address explicitly if
// it really is meant to be reachable.
func TestSocks5UnroutedIPLiteralIsRefused(t *testing.T) {
	reachable, hits := tcpEcho(t, "direct")
	routerAddr, _ := sandbox(t)

	dialer, err := proxy.SOCKS5("tcp", routerAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("socks5 dialer: %v", err)
	}
	conn, err := dialer.Dial("tcp", reachable) // 127.0.0.1:port — an address
	if err == nil {
		conn.Close()
		t.Fatal("an address nobody forwarded was dialled; a client that resolves names " +
			"itself would bypass the allowlist entirely")
	}
	if hits.Load() != 0 {
		t.Fatal("the target was reached anyway")
	}
}

// Whitelisting an address is how an address becomes reachable: the route is the
// operator's decision, taken on the controlplane, and by name or by address it
// is honoured the same way.
func TestSocks5ForwardedIPLiteralIsAllowed(t *testing.T) {
	tunnelSide, tunnelHits := tcpEcho(t, "controlplane")
	sandboxSide, _ := tcpEcho(t, "unused")

	routerAddr, client := sandbox(t)
	if err := client.Proxy().ForwardTo(sandboxSide, tunnelSide); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	conn := socksDial(t, routerAddr, sandboxSide)
	if got := ask(t, conn, "ping"); got != "controlplane: ping" {
		t.Fatalf("answer = %q, want the controlplane's target", got)
	}
	if tunnelHits.Load() == 0 {
		t.Fatal("the forwarded address did not go through the tunnel")
	}
}

// The same port still serves HTTP: that is what makes one address enough for
// HTTP_PROXY and ALL_PROXY together.
func TestRouterServesHTTPAndSocks5OnTheSamePort(t *testing.T) {
	controlplaneOnly, _ := tcpEcho(t, "controlplane")
	routerAddr, client := sandbox(t)

	if err := client.Proxy().ForwardTo("db.corp:5432", controlplaneOnly); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	// SOCKS5 …
	conn := socksDial(t, routerAddr, "db.corp:5432")
	if got := ask(t, conn, "ping"); got != "controlplane: ping" {
		t.Fatalf("socks5 answer = %q", got)
	}

	// … and an ordinary proxied HTTP request, on the same address. Its target
	// is a real HTTP server: the echo above speaks nothing but bytes.
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "web")
	}))
	defer web.Close()

	httpClient := routerClient(t, routerAddr)
	if got := getBody(t, httpClient, web.URL+"/"); got != "web" {
		t.Fatalf("HTTP through the router = %q, want web", got)
	}
}

// Interception is not an HTTP-only affair either: a TLS connection opened
// through SOCKS5 reaches the controlplane as a CONNECT, so it meets the MITM CA
// and the configured headers exactly as it would through HTTPS_PROXY.
func TestSocks5TLSTargetIsInterceptedAndInjected(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "auth=%s", r.Header.Get("Authorization"))
	}))
	defer backend.Close()

	ts, server := startTunnelServer(t)
	defer ts.Close()

	routerAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := server.StartProxy(routerAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	ca := generateTestCA(t)
	client := vtunnel.NewClient(wsURL(ts), vtunnel.WithMitm(ca))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	if err := client.Proxy().ForwardTo("api.corp", backend.Listener.Addr().String(),
		vtunnel.WithHeader("Authorization", "Bearer through-socks")); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	// An HTTPS client whose only way out is SOCKS5.
	dialer, err := proxy.SOCKS5("tcp", routerAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("socks5 dialer: %v", err)
	}
	caPool := x509.NewCertPool()
	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	caPool.AddCert(caCert)

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
	}

	resp, err := httpClient.Get("https://api.corp/whoami")
	if err != nil {
		t.Fatalf("GET through socks5: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != "auth=Bearer through-socks" {
		t.Fatalf("body = %q: the credential was not injected on the SOCKS5 path", body)
	}
}

// UDP has no way through this tunnel, and a client is told so at once rather
// than left waiting for an association that is not coming. It is what
// mitmproxy answers too.
func TestSocks5UDPAssociateIsRefused(t *testing.T) {
	routerAddr, _ := sandbox(t)

	conn, err := net.DialTimeout("tcp", routerAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial router: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Greeting, no authentication.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	selection := make([]byte, 2)
	if _, err := io.ReadFull(conn, selection); err != nil {
		t.Fatalf("read method selection: %v", err)
	}

	// UDP ASSOCIATE for 0.0.0.0:0, the usual way to ask.
	if _, err := conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("write request: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != 0x07 {
		t.Fatalf("reply = % x, want 05 07 … (command not supported)", reply)
	}
}
