package vtunnel_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

// Alt-Svc offers the client another way to the same origin, over HTTP/3 — which
// is UDP, which this proxy neither terminates nor routes. A client that takes
// the offer leaves the tunnel altogether: no interception, no injected
// credential, and no error anywhere to notice it by.

// mitmproxy rewrites the header to point at itself and calls
// keeping it "may cause clients to bypass the proxy"; having no h3 port to
// point at, we drop it.
func TestAltSvcIsStrippedFromUpstreamResponses(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
		w.Header().Add("Alt-Svc", `h3-29=":443"`)
		fmt.Fprint(w, "ok")
	}))
	defer backend.Close()

	addr, ca := gapProxy(t, backend.Listener.Addr().String())

	t.Run("through MITM", func(t *testing.T) {
		tc := connectThenTLS(t, addr, "probe.test:443", "probe.test", "", ca)
		resp := requestOver(t, tc, "GET / HTTP/1.1\r\nHost: probe.test\r\n\r\n")
		io.ReadAll(resp.Body)
		resp.Body.Close()
		if got := resp.Header.Values("Alt-Svc"); len(got) != 0 {
			t.Fatalf("client saw Alt-Svc %q: it may now reach the upstream over HTTP/3, "+
				"straight past this proxy", got)
		}
	})

	t.Run("cleartext through the proxy", func(t *testing.T) {
		proxyURL, _ := url.Parse("http://" + addr)
		client := &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		}
		resp, err := client.Get("http://probe.test/")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		if got := resp.Header.Values("Alt-Svc"); len(got) != 0 {
			t.Fatalf("client saw Alt-Svc %q on the cleartext path", got)
		}
	})

	t.Run("through the sandbox egress proxy", func(t *testing.T) {
		sandbox := vtunnel.NewServer()
		defer sandbox.Close()
		if err := sandbox.StartProxy("127.0.0.1:0"); err != nil {
			t.Fatalf("StartProxy: %v", err)
		}
		proxyURL, _ := url.Parse("http://" + sandbox.Egress().Addr().String())
		client := &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		}
		resp, err := client.Get(backend.URL + "/")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		if got := resp.Header.Values("Alt-Svc"); len(got) != 0 {
			t.Fatalf("client saw Alt-Svc %q through the egress proxy", got)
		}
	})
}
