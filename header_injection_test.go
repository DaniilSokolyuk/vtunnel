package vtunnel_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

// TestProxyMitmHeaderInjection drives HTTPS via a MITM proxy with configured
// per-domain headers and verifies the backend sees them.
func TestProxyMitmHeaderInjection(t *testing.T) {
	type hdr struct {
		name, value string
	}
	cases := []struct {
		name         string
		configure    []hdr
		clientHeader *hdr
		wantPresent  []hdr
		wantAbsent   []string
	}{
		{
			name:        "single injected",
			configure:   []hdr{{"Authorization", "Bearer xxx"}},
			wantPresent: []hdr{{"Authorization", "Bearer xxx"}},
		},
		{
			name: "multiple injected",
			configure: []hdr{
				{"Authorization", "Bearer xxx"},
				{"X-Env", "preview"},
			},
			wantPresent: []hdr{
				{"Authorization", "Bearer xxx"},
				{"X-Env", "preview"},
			},
		},
		{
			name:       "headerless unaffected",
			configure:  nil,
			wantAbsent: []string{"Authorization", "X-Env"},
		},
		{
			name:         "app header overridden",
			configure:    []hdr{{"Authorization", "Bearer real"}},
			clientHeader: &hdr{"Authorization", "fake"},
			wantPresent:  []hdr{{"Authorization", "Bearer real"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(http.Header)
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, vs := range r.Header {
					seen[k] = append([]string(nil), vs...)
				}
				fmt.Fprint(w, "ok")
			}))
			defer backend.Close()

			ca := generateTestCA(t)
			proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
			proxyPort := freePort(t)
			proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
			if err := proxy.Start(proxyAddr); err != nil {
				t.Fatalf("StartProxy error: %v", err)
			}
			defer proxy.Close()

			var opts []vtunnel.ForwardOption
			for _, e := range tc.configure {
				opts = append(opts, vtunnel.WithHeader(e.name, e.value))
			}
			proxy.ForwardTo("api.test:443", backend.Listener.Addr().String(), opts...)

			client := newMitmProxyClient(t, proxyAddr)
			req, err := http.NewRequest(http.MethodGet, "https://api.test/", nil)
			if err != nil {
				t.Fatalf("NewRequest error: %v", err)
			}
			if tc.clientHeader != nil {
				req.Header.Set(tc.clientHeader.name, tc.clientHeader.value)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("HTTPS GET error: %v", err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			for _, want := range tc.wantPresent {
				got := seen.Get(want.name)
				if got != want.value {
					t.Fatalf("header %q: got %q, want %q (full=%v)", want.name, got, want.value, seen)
				}
			}
			for _, name := range tc.wantAbsent {
				if got := seen.Get(name); got != "" {
					t.Fatalf("header %q: got %q, want absent", name, got)
				}
			}
		})
	}
}

// TestProxyMitmDifferentHeadersPerForward verifies headers on one forward
// never leak into requests for a different forward.
func TestProxyMitmDifferentHeadersPerForward(t *testing.T) {
	backendA := captureBackend(t)
	defer backendA.srv.Close()
	backendB := captureBackend(t)
	defer backendB.srv.Close()

	ca := generateTestCA(t)
	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	proxyPort := freePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if err := proxy.Start(proxyAddr); err != nil {
		t.Fatalf("StartProxy error: %v", err)
	}
	defer proxy.Close()

	proxy.ForwardTo("a.test:443", backendA.srv.Listener.Addr().String(), vtunnel.WithHeader("X-Who", "alpha"))
	proxy.ForwardTo("b.test:443", backendB.srv.Listener.Addr().String(), vtunnel.WithHeader("X-Who", "bravo"))

	client := newMitmProxyClient(t, proxyAddr)

	for _, host := range []string{"a.test", "b.test"} {
		resp, err := client.Get("https://" + host + "/")
		if err != nil {
			t.Fatalf("GET %s: %v", host, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	if got := backendA.seen().Get("X-Who"); got != "alpha" {
		t.Fatalf("backend A X-Who = %q, want alpha", got)
	}
	if got := backendB.seen().Get("X-Who"); got != "bravo" {
		t.Fatalf("backend B X-Who = %q, want bravo", got)
	}
}

// TestProxyPlainHTTPHeaderInjection verifies the non-CONNECT code path also
// injects configured headers.
func TestProxyPlainHTTPHeaderInjection(t *testing.T) {
	b := captureBackend(t)
	defer b.srv.Close()

	// A CA even though nothing on this path is decrypted: injection is refused
	// without one, since the same route would silently drop the header the
	// moment the domain were reached over HTTPS.
	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(generateTestCA(t)))
	proxyPort := freePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if err := proxy.Start(proxyAddr); err != nil {
		t.Fatalf("StartProxy error: %v", err)
	}
	defer proxy.Close()

	if err := proxy.ForwardTo("plain.test:80", b.srv.Listener.Addr().String(),
		vtunnel.WithHeader("Authorization", "Bearer plain")); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp, err := client.Get("http://plain.test/")
	if err != nil {
		t.Fatalf("plain GET error: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if got := b.seen().Get("Authorization"); got != "Bearer plain" {
		t.Fatalf("Authorization = %q, want 'Bearer plain'", got)
	}
}

// TestClientForwardWithHeader exercises the whole architecture: an application
// in the sandbox talks to the router, which chains through the tunnel to the
// controlplane proxy, which is the only side holding the CA and the headers.
func TestClientForwardWithHeader(t *testing.T) {
	b := captureBackend(t)
	defer b.srv.Close()

	// --- Sandbox: router only. No CA, no headers. ---
	server := vtunnel.NewServer()
	routerAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := server.StartProxy(routerAddr); err != nil {
		t.Fatalf("StartProxy error: %v", err)
	}
	defer server.CloseProxy()

	tunnelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		server.HandleConn(conn)
	}))
	defer tunnelServer.Close()

	// --- Controlplane: CA and credentials live here. ---
	ca := generateTestCA(t)
	client := vtunnel.NewClient(wsURL(tunnelServer), vtunnel.WithMitm(ca))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect error: %v", err)
	}
	defer client.Close()

	client.Proxy().ForwardTo("api.test:443", b.srv.Listener.Addr().String(),
		vtunnel.WithHeader("Authorization", "Bearer e2e"),
		vtunnel.WithHeader("X-Env", "preview"),
	)
	time.Sleep(100 * time.Millisecond)

	// The application only ever sees the router.
	httpClient := newMitmProxyClient(t, routerAddr)
	resp, err := httpClient.Get("https://api.test/hello")
	if err != nil {
		t.Fatalf("HTTPS GET error: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	seen := b.seen()
	if got := seen.Get("Authorization"); got != "Bearer e2e" {
		t.Fatalf("Authorization = %q, want 'Bearer e2e' (full=%v)", got, seen)
	}
	if got := seen.Get("X-Env"); got != "preview" {
		t.Fatalf("X-Env = %q, want preview (full=%v)", got, seen)
	}
}

// --- helpers ---

func newMitmProxyClient(t *testing.T, proxyAddr string) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("Parse proxy URL: %v", err)
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// captureBackend records the request headers seen on the most recent request.
type capturing struct {
	srv    *httptest.Server
	lastCh chan http.Header
}

func (c *capturing) seen() http.Header {
	select {
	case h := <-c.lastCh:
		return h
	case <-time.After(1 * time.Second):
		return http.Header{}
	}
}

func captureBackend(t *testing.T) *capturing {
	t.Helper()
	c := &capturing{lastCh: make(chan http.Header, 16)}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := http.Header{}
		for k, vs := range r.Header {
			h[k] = append([]string(nil), vs...)
		}
		select {
		case c.lastCh <- h:
		default:
		}
		fmt.Fprint(w, "ok")
	}))
	return c
}
