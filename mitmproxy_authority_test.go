package vtunnel_test

// The authority of a CONNECT is chosen by the client, and on the sandbox side
// the client is the untrusted party. It is matched against the route table, and
// what is learned about it is stored under it — so an authority that is not a
// hostname is an authority that can be aimed at more than one route.

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

// A wildcard route is a pattern, not a name. Naming the pattern itself as the
// authority made an exact match against the route key — and everything learned
// from that connection was then stored under the pattern, where the ordinary
// wildcard lookup finds it for every domain underneath.
//
// The client controls its own TLS, so it can always fail the interception
// handshake in a way that reads as certificate pinning. Doing that once under
// the pattern used to turn interception off for the whole subtree, including
// domains the sandbox never named, for as long as the exclusion lasted.
func TestWildcardPatternIsNotAValidConnectAuthority(t *testing.T) {
	echo, _ := tcpEcho(t, "upstream")

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("*.corp", echo); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	conn, err := net.DialTimeout("tcp", p.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	fmt.Fprint(conn, "CONNECT *.corp:443 HTTP/1.1\r\nHost: *.corp:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		// Refused before an answer is fine too.
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("a CONNECT whose authority is the wildcard pattern itself was accepted: " +
			"whatever is learned from it is stored where every domain under the pattern will find it")
	}
}

// The property that matters underneath: failing interception for one domain
// must not turn it off for another. The sandbox can always refuse the generated
// certificate, so this is the difference between opting one domain out and
// opting out a whole subtree.
func TestRefusingInterceptionOnlyAffectsTheDomainThatRefused(t *testing.T) {
	echo, _ := tcpEcho(t, "upstream")

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("*.corp", echo); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	// Pin: refuse the generated leaf, which is what a pinning client looks like.
	pinned := connectAndFailTLS(t, p.Addr().String(), "one.corp:443")
	_ = pinned

	// Another domain under the same pattern must still be intercepted, which
	// shows as a certificate this test's CA can verify.
	conn, err := net.DialTimeout("tcp", p.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(conn, "CONNECT two.corp:443 HTTP/1.1\r\nHost: two.corp:443\r\n\r\n")
	if _, err := http.ReadResponse(bufio.NewReader(conn), nil); err != nil {
		t.Fatalf("CONNECT two.corp: %v", err)
	}

	roots := x509.NewCertPool()
	leaf, _ := x509.ParseCertificate(ca.Certificate[0])
	roots.AddCert(leaf)
	tc := tls.Client(conn, &tls.Config{ServerName: "two.corp", RootCAs: roots})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("two.corp was not intercepted after one.corp refused interception: %v", err)
	}
}

// connectAndFailTLS opens a tunnel and refuses whatever certificate it is
// offered, the way a client that pins its upstream does.
func connectAndFailTLS(t *testing.T, proxyAddr, authority string) error {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
	if _, err := http.ReadResponse(bufio.NewReader(conn), nil); err != nil {
		t.Fatalf("CONNECT %s: %v", authority, err)
	}
	// An empty pool trusts nothing, so the handshake ends in a certificate alert.
	tc := tls.Client(conn, &tls.Config{ServerName: "one.corp", RootCAs: x509.NewCertPool()})
	return tc.Handshake()
}
