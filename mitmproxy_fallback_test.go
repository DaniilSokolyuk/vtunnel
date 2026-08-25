package vtunnel_test

// When interception turns out to be impossible the proxy may fall back to
// piping the connection through untouched. That is the right answer for a
// client that pins its upstream's certificate — but only when the pipe still
// goes where the route said, and only when nothing was going to be added to the
// traffic on the way.

import (
	"crypto/tls"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

// sniRecorder is a TLS server that answers nothing and records the server name
// it was asked for, so a test can see which name the proxy presented.
func sniRecorder(t *testing.T, certName string) (addr string, names func() []string) {
	t.Helper()
	leaf, _ := selfSignedFor(t, certName)

	var mu sync.Mutex
	var seen []string
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{leaf},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			seen = append(seen, hello.ServerName)
			mu.Unlock()
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.(*tls.Conn).Handshake()
				time.Sleep(200 * time.Millisecond)
			}()
		}
	}()

	return ln.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

// A route that renames the server — tls:// with WithSNI — cannot be piped when
// interception fails, because the pipe carries the client's own name, not the
// one the route configured. The connection then goes to an upstream whose TLS
// identity was never negotiated for it: it cannot succeed, and it replaces an
// accurate error ("the upstream's certificate does not check out, and here is
// the CA to add") with a misleading one attributed to the wrong domain.
func TestRenamingRouteIsNotSilentlyPiped(t *testing.T) {
	upstream, names := sniRecorder(t, "internal-gw")

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	// The proxy is not given the upstream's CA, so interception fails on the
	// upstream handshake.
	if err := p.ForwardTo("api.example.com", "tls://"+upstream,
		vtunnel.WithSNI("internal-gw")); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	client := proxyClientFor(t, p.Addr().String(), ca)
	for range 2 {
		if resp, err := client.Get("https://api.example.com/"); err == nil {
			resp.Body.Close()
		}
	}

	for _, name := range names() {
		if name == "api.example.com" {
			t.Fatalf("the upstream was asked for %q; the route configures %q, and a pipe "+
				"cannot honour that — SNIs seen: %v", name, "internal-gw", names())
		}
	}
}

// A tls:// target written as an address is reached by that address: Go does not
// send an IP as SNI and verifies against the IP instead, which works when the
// upstream's certificate carries an IP SAN — and plenty do.
//
// When it does not, the upstream handshake can never succeed. That route also
// renames the server, so it is not piped either: it fails the same way every
// time, visibly, rather than quietly answering 200 with no interception behind
// it and the configured middleware never running.
func TestTLSTargetByAddressFailsLoudlyRatherThanPiping(t *testing.T) {
	// Issued for a name, so verifying it against the address it is reached by
	// cannot succeed.
	upstream, names := sniRecorder(t, "internal-gw")

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("api.corp", "tls://"+upstream); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	client := proxyClientFor(t, p.Addr().String(), ca)
	for i := range 3 {
		resp, err := client.Get("https://api.corp/")
		if err != nil {
			continue // unusable, which is the honest answer
		}
		status := resp.StatusCode
		resp.Body.Close()
		if status == http.StatusOK {
			t.Fatalf("request %d answered 200 through a pipe: this route renames the "+
				"server, and a pipe cannot honour that (SNIs seen: %v)", i, names())
		}
	}
}
