package vtunnel

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// serveProxyHandler runs p as a plain http.Handler, the shape doc.go advertises
// for a standalone proxy, and returns its address.
func serveProxyHandler(t *testing.T, p *MITMProxy) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: p}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func proxyHTTPClient(proxyAddr string, ca tls.Certificate, h2 bool) *http.Client {
	leaf, _ := x509.ParseCertificate(ca.Certificate[0])
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
			TLSClientConfig:   &tls.Config{RootCAs: roots},
			ForceAttemptHTTP2: h2,
		},
	}
}

// A MITMProxy used as an http.Handler is a supported shape — ServeHTTP is
// exported and doc.go describes a standalone proxy — but interception was gated
// on state only Start installed. Declaring a route with headers then succeeded,
// and every request reached the upstream with the credential missing: a failure
// with no error and no missing response to notice, which is exactly what
// errNoMitmCA exists to prevent.
func TestHandlerModeInterceptsAndInjects(t *testing.T) {
	seen := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case seen <- r.Header.Get("Authorization"):
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
	defer p.Close()

	client := proxyHTTPClient(serveProxyHandler(t, p), ca, false)
	resp, err := client.Get("https://api.corp/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	select {
	case got := <-seen:
		if got != "Bearer secret" {
			t.Fatalf("upstream saw Authorization %q, want the injected credential", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never saw the request")
	}
}

// net/http reports TLS state by asserting the concrete *tls.Conn, which the
// one-shot listener's wrapper hid — so every request a MITM'd HTTP/1.1
// connection carried looked like cleartext to handlers and middleware.
func TestInterceptedHTTP1RequestCarriesTLSState(t *testing.T) {
	ca := generateProxyTestCA(t)
	p := NewMITMProxy(WithMitmCA(ca))

	states := make(chan *tls.ConnectionState, 1)
	err := p.Handle("api.corp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case states <- r.TLS:
		default:
		}
		fmt.Fprint(w, "ok")
	}))
	if err != nil {
		t.Fatalf("Handle: %v", err)
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
	io.Copy(io.Discard, resp.Body)

	select {
	case state := <-states:
		if state == nil {
			t.Fatal("handler saw r.TLS == nil on an intercepted HTTPS request")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler never ran")
	}
}
