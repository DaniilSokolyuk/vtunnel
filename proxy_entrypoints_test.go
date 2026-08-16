package vtunnel_test

// Every way in, against every kind of route.
//
// The proxy can be reached three ways — an ordinary proxied request, a CONNECT
// tunnel, or SOCKS5 — and a route can be a target, an in-process handler, or
// absent. What must not vary is the answer: the same domain behaves the same
// whichever door the client came through, and in particular a configured
// header is injected on all of them. A difference here is not a curiosity, it
// is a credential that silently did not travel.

import (
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

	"golang.org/x/net/proxy"

	"github.com/vivid-money/vtunnel"
)

// chain is the whole thing standing up: an application's proxy address in a
// sandbox, a tunnel, and a controlplane proxy holding the CA and the routes.
type chain struct {
	routerAddr string
	ca         tls.Certificate
	// unrouted is a plain HTTP server nobody forwarded, reachable from the
	// "sandbox" — which is this process, so its own address stands in for the
	// public internet.
	unroutedAddr string
	// rawTarget answers non-HTTP bytes on the controlplane's side.
	rawTargetAddr string
}

func newChain(t *testing.T) *chain {
	t.Helper()

	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "web %s auth=%s", r.URL.Path, r.Header.Get("Authorization"))
	}))
	t.Cleanup(web.Close)

	unrouted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "unrouted")
	}))
	t.Cleanup(unrouted.Close)

	rawTarget, _ := tcpEcho(t, "raw")

	ts, server := startTunnelServer(t)
	t.Cleanup(ts.Close)

	routerAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := server.StartProxy(routerAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	t.Cleanup(server.CloseProxy)

	ca := generateTestCA(t)
	client := vtunnel.NewClient(wsURL(ts), vtunnel.WithMitm(ca))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	p := client.Proxy()
	// A target route on the default ports, with a credential the controlplane
	// attaches and the sandbox never sees.
	if err := p.ForwardTo("target.corp", web.Listener.Addr().String(),
		vtunnel.WithHeader("Authorization", "Bearer injected")); err != nil {
		t.Fatalf("ForwardTo target.corp: %v", err)
	}
	// The same, on a port that carries no HTTP at all.
	if err := p.ForwardTo("target.corp:5432", rawTarget); err != nil {
		t.Fatalf("ForwardTo target.corp:5432: %v", err)
	}
	// A route served in this process, on the default ports and on one that is
	// not HTTP.
	inProcess := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "handled %s", r.URL.Path)
	})
	p.Handle("handler.corp", inProcess)
	p.Handle("handler.corp:5432", inProcess)

	time.Sleep(200 * time.Millisecond) // let the routes reach the sandbox

	return &chain{
		routerAddr:    routerAddr,
		ca:            ca,
		unroutedAddr:  unrouted.Listener.Addr().String(),
		rawTargetAddr: rawTarget,
	}
}

// caPool trusts the MITM CA, so an intercepted response verifies and an
// unintercepted one does not.
func (c *chain) caPool(t *testing.T) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	leaf, err := x509.ParseCertificate(c.ca.Certificate[0])
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	pool.AddCert(leaf)
	return pool
}

// viaHTTPProxy is a client configured the way HTTP_PROXY and HTTPS_PROXY
// configure one: plain requests go in absolute-URI form, TLS goes through
// CONNECT.
func (c *chain) viaHTTPProxy(t *testing.T) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse("http://" + c.routerAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			TLSClientConfig:   &tls.Config{RootCAs: c.caPool(t)},
			DisableKeepAlives: true,
		},
	}
}

// viaSocks5 is a client configured the way ALL_PROXY=socks5h:// configures one:
// every connection is opened through SOCKS5, and the name travels unresolved.
func (c *chain) viaSocks5(t *testing.T) *http.Client {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", c.routerAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("socks5 dialer: %v", err)
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Dial:              dialer.Dial,
			TLSClientConfig:   &tls.Config{RootCAs: c.caPool(t)},
			DisableKeepAlives: true,
		},
	}
}

func (c *chain) socksDialer(t *testing.T) proxy.Dialer {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", c.routerAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("socks5 dialer: %v", err)
	}
	return dialer
}

func get(t *testing.T, client *http.Client, rawURL string) string {
	t.Helper()
	resp, err := client.Get(rawURL)
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

// TestEveryEntryPointAgainstEveryRoute is the table the rest of the suite
// exists to make true: HTTP proxy and SOCKS5, against target routes, in-process
// handlers and no route at all.
func TestEveryEntryPointAgainstEveryRoute(t *testing.T) {
	c := newChain(t)

	entries := []struct {
		name   string
		client func(*testing.T) *http.Client
	}{
		{name: "http-proxy", client: c.viaHTTPProxy},
		{name: "socks5", client: c.viaSocks5},
	}

	requests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "cleartext to a target route",
			url:  "http://target.corp/one",
			// The credential is attached on the controlplane, whichever way the
			// request arrived: that is the whole promise of a forward.
			want: "web /one auth=Bearer injected",
		},
		{
			name: "TLS to a target route",
			url:  "https://target.corp/two",
			want: "web /two auth=Bearer injected",
		},
		{
			name: "cleartext to a handler route",
			url:  "http://handler.corp/three",
			want: "handled /three",
		},
		{
			name: "TLS to a handler route",
			url:  "https://handler.corp/four",
			want: "handled /four",
		},
	}

	for _, entry := range entries {
		for _, req := range requests {
			t.Run(entry.name+": "+req.name, func(t *testing.T) {
				if got := get(t, entry.client(t), req.url); got != req.want {
					t.Fatalf("body = %q, want %q", got, req.want)
				}
			})
		}
	}

	// Everything below is one entry point only, because the case is about what
	// that entry point can express.

	t.Run("socks5: raw TCP to a target route", func(t *testing.T) {
		conn, err := c.socksDialer(t).Dial("tcp", "target.corp:5432")
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if got := ask(t, conn, "SELECT 1"); got != "raw: SELECT 1" {
			t.Fatalf("answer = %q, want the raw target's", got)
		}
	})

	t.Run("socks5: raw TCP to a handler route is refused", func(t *testing.T) {
		conn, err := c.socksDialer(t).Dial("tcp", "handler.corp:5432")
		if err != nil {
			return // refused outright is fine too
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		conn.Write([]byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f})
		if _, err := io.ReadAll(conn); err != nil {
			t.Fatalf("read: %v", err)
		}
		// Closed without an answer: a handler has nowhere to pipe bytes it
		// cannot parse.
	})

	t.Run("socks5: an unrouted name egresses directly", func(t *testing.T) {
		_, port, _ := net.SplitHostPort(c.unroutedAddr)
		if got := get(t, c.viaSocks5(t), "http://localhost:"+port+"/"); got != "unrouted" {
			t.Fatalf("body = %q, want unrouted", got)
		}
	})

	t.Run("socks5: an unrouted address is refused", func(t *testing.T) {
		conn, err := c.socksDialer(t).Dial("tcp", c.unroutedAddr)
		if err == nil {
			conn.Close()
			t.Fatal("an address nobody forwarded was dialled")
		}
		if !strings.Contains(err.Error(), "not allowed") {
			t.Fatalf("err = %v, want a ruleset refusal", err)
		}
	})

	t.Run("http-proxy: an unrouted name egresses directly", func(t *testing.T) {
		_, port, _ := net.SplitHostPort(c.unroutedAddr)
		if got := get(t, c.viaHTTPProxy(t), "http://localhost:"+port+"/"); got != "unrouted" {
			t.Fatalf("body = %q, want unrouted", got)
		}
	})

	t.Run("an unrouted TLS host is not intercepted", func(t *testing.T) {
		// Its own certificate is the evidence: a MITM'd connection would carry
		// one signed by the CA this client trusts, and nothing else would.
		elsewhere := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "elsewhere")
		}))
		elsewhere.StartTLS()
		defer elsewhere.Close()

		_, port, _ := net.SplitHostPort(elsewhere.Listener.Addr().String())
		client := c.viaSocks5(t)
		client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: c.caPool(t)}

		_, err := client.Get("https://localhost:" + port + "/")
		if err == nil {
			t.Fatal("the CA verified a host it never signed for: the connection was intercepted")
		}
	})
}
