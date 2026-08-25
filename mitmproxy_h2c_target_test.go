package vtunnel_test

// An h2c:// target: cleartext HTTP/2 stated rather than discovered.
//
// The proxy can find an h2c upstream by asking it — see probeH2C — and that is
// the right default for a target nobody described. But asking has two costs
// worth being able to avoid: a dial and a wait for the peer's SETTINGS on the
// first request, and, more sharply, the question is only ever asked when the
// client side is HTTP/2 too. An h2c-only upstream behind an HTTP/1.1 client is
// therefore unreachable by discovery alone, and reachable by saying so.

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/vivid-money/vtunnel"
)

// startH2COnlyBackend serves cleartext HTTP/2 with prior knowledge and nothing
// else. Unlike h2c.NewHandler, which also answers HTTP/1.1, this one expects the
// client preface — so a request that arrives as HTTP/1.1 gets no answer at all.
// That is what makes it able to tell discovery apart from a statement.
//
// It reports how many connections were accepted, which is how a test sees a
// probe that should not have happened.
func startH2COnlyBackend(t *testing.T, body string) (addr string, accepted func() int32) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	var conns atomic.Int32
	srv := &http2.Server{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go srv.ServeConn(conn, &http2.ServeConnOpts{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
					fmt.Fprint(w, body)
				}),
			})
		}
	}()
	return ln.Addr().String(), conns.Load
}

// h2ProxyClient reaches everything through the proxy and offers HTTP/2 to it.
func h2ProxyClient(t *testing.T, proxyAddr string, ca tls.Certificate) *http.Client {
	t.Helper()
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(mustParseURL(t, "http://"+proxyAddr)),
			TLSClientConfig:   &tls.Config{RootCAs: caPoolFor(t, ca)},
			ForceAttemptHTTP2: true,
		},
	}
}

// startProxyWithRoute stands up an intercepting proxy carrying one route.
func startProxyWithRoute(t *testing.T, target string, opts ...vtunnel.ForwardOption) (*vtunnel.MITMProxy, tls.Certificate) {
	t.Helper()

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("api.corp", target, opts...); err != nil {
		t.Fatalf("ForwardTo(%q): %v", target, err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(p.Close)
	return p, ca
}

// Stated, so nothing is asked. One request costs the upstream exactly one
// connection: a probe would be a second.
func TestH2CTargetIsSpokenWithoutProbing(t *testing.T) {
	upstream, accepted := startH2COnlyBackend(t, "h2c-ok")

	p, ca := startProxyWithRoute(t, "h2c://"+upstream)

	resp, err := h2ProxyClient(t, p.Addr().String(), ca).Get("https://api.corp/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != "h2c-ok" {
		t.Fatalf("body = %q, want %q", body, "h2c-ok")
	}
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Errorf("Grpc-Status trailer = %q, want 0: a gRPC status has to survive the hop", got)
	}
	if n := accepted(); n != 1 {
		t.Errorf("the upstream accepted %d connections, want 1: an h2c:// target is stated, not probed", n)
	}
}

// The case discovery cannot reach, and the reason the prefix exists. probeH2C
// is consulted only when the client side is HTTP/2, so an HTTP/1.1 client in
// front of an h2c-only upstream never gets there.
func TestH2CTargetReachesAnH2COnlyUpstreamFromAnHTTP1Client(t *testing.T) {
	upstream, _ := startH2COnlyBackend(t, "h2c-from-h1")

	t.Run("stated", func(t *testing.T) {
		p, ca := startProxyWithRoute(t, "h2c://"+upstream)

		// proxyClientFor leaves ForceAttemptHTTP2 off, so the client offers
		// http/1.1 only and the proxy serves it over HTTP/1.1.
		resp, err := proxyClientFor(t, p.Addr().String(), ca).Get("https://api.corp/x")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if string(body) != "h2c-from-h1" {
			t.Fatalf("status %d, body %q; want the h2c upstream's answer", resp.StatusCode, body)
		}
	})

	t.Run("left to discovery", func(t *testing.T) {
		p, ca := startProxyWithRoute(t, upstream)

		resp, err := proxyClientFor(t, p.Addr().String(), ca).Get("https://api.corp/x")
		if err != nil {
			// A transport-level failure is also "did not reach it", which is
			// the point being pinned.
			return
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)

		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502: an HTTP/1.1 client never triggers the h2c probe, "+
				"so an unstated h2c-only upstream is out of reach", resp.StatusCode)
		}
	})
}

// Left unstated with an HTTP/2 client, the upstream is found by asking — the
// behaviour the prefix is an alternative to, not a replacement for. The route
// carries a header, so this also walks the whole chain: the TLS question is
// asked first, answered no, and the h2c question is asked after it.
func TestUnstatedH2CIsFoundByProbing(t *testing.T) {
	upstream, _ := startH2COnlyBackend(t, "probed-ok")

	p, ca := startProxyWithRoute(t, upstream, vtunnel.WithHeader("X-Injected", "yes"))

	resp, err := h2ProxyClient(t, p.Addr().String(), ca).Get("https://api.corp/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != "probed-ok" {
		t.Fatalf("status %d, body %q; want the h2c upstream's answer", resp.StatusCode, body)
	}
}

// Stating the scheme excuses the route from being asked whether its upstream
// speaks TLS, and the header still lands. Both halves matter: h2c:// is
// cleartext said outright, which is the same promise http:// makes.
func TestH2CTargetInjectsHeadersWithoutATLSQuestion(t *testing.T) {
	seen := make(chan string, 1)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	srv := &http2.Server{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.ServeConn(conn, &http2.ServeConnOpts{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					select {
					case seen <- r.Header.Get("Authorization"):
					default:
					}
					fmt.Fprint(w, "ok")
				}),
			})
		}
	}()

	p, ca := startProxyWithRoute(t, "h2c://"+ln.Addr().String(),
		vtunnel.WithHeader("Authorization", "Bearer injected"))

	resp, err := h2ProxyClient(t, p.Addr().String(), ca).Get("https://api.corp/x")
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

// h2c:// and WithSNI contradict each other — one says cleartext, the other
// names the server for a TLS handshake. Taking either silently would mean the
// route does something the caller did not ask for, so it is refused where it is
// declared.
func TestH2CTargetRefusesAnSNI(t *testing.T) {
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(generateTestCA(t)))

	err := p.ForwardTo("api.corp", "h2c://10.0.0.9:13002", vtunnel.WithSNI("api.corp"))
	if err == nil {
		t.Fatal("ForwardTo accepted h2c:// together with WithSNI")
	}
	if !strings.Contains(err.Error(), "SNI") {
		t.Errorf("error = %v, want it to name the contradiction", err)
	}
}
