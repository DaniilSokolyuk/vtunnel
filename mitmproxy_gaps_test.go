package vtunnel_test

// Four protocol corners, found by reading mitmproxy's own tests against ours.
// Each one is quiet: nothing errors, and what goes wrong is a request that
// took a path nobody chose.

import (
	"bufio"
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

	"github.com/vivid-money/vtunnel"
)

// gapProxy is a standalone intercepting proxy with one forwarded domain and a
// credential attached to it, which is what makes "did interception happen"
// answerable: a pipe cannot inject a header.
func gapProxy(t *testing.T, upstream string) (addr string, ca tls.Certificate) {
	t.Helper()
	ca = generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("probe.test", upstream,
		vtunnel.WithHeader("Authorization", "Bearer injected")); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(p.Close)
	return p.Addr().String(), ca
}

func caPoolFor(t *testing.T, ca tls.Certificate) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	leaf, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	pool.AddCert(leaf)
	return pool
}

// connectThenTLS opens a CONNECT tunnel, writes trailing after the request
// headers, and completes a TLS handshake inside it.
func connectThenTLS(t *testing.T, proxyAddr, authority, serverName, trailing string, ca tls.Certificate) *tls.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n%s", authority, authority, trailing)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: %s", resp.Status)
	}

	tc := tls.Client(conn, &tls.Config{ServerName: serverName, RootCAs: caPoolFor(t, ca)})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("TLS handshake inside the tunnel: %v", err)
	}
	return tc
}

func requestOver(t *testing.T, conn net.Conn, request string) *http.Response {
	t.Helper()
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp
}

// 1. A client is allowed to leave stray CRLFs after the CONNECT headers — RFC
// 9112 §2.2 says a recipient may ignore them, and real ones send them. Reading
// them as the start of the tunnelled stream made the ClientHello look like
// something that is not TLS, so interception was quietly abandoned for a byte
// pipe: no decryption, no injected credential, nothing but a log line that
// reads like an ordinary cleartext tunnel.
func TestExtraCRLFAfterConnectStillIntercepts(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "auth=%s", r.Header.Get("Authorization"))
	}))
	defer backend.Close()

	addr, ca := gapProxy(t, backend.Listener.Addr().String())

	tc := connectThenTLS(t, addr, "probe.test:443", "probe.test", "\r\n\r\n", ca)
	resp := requestOver(t, tc, "GET / HTTP/1.1\r\nHost: probe.test\r\n\r\n")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != "auth=Bearer injected" {
		t.Fatalf("body = %q: the tunnel was piped instead of intercepted, so the "+
			"credential never made it", body)
	}
}

// The same padding through the sandbox router, where it used to be copied
// verbatim into the upstream and arrive in front of the ClientHello.
func TestExtraCRLFThroughTheRouter(t *testing.T) {
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
	if err := client.Proxy().ForwardTo("probe.test", backend.Listener.Addr().String(),
		vtunnel.WithHeader("Authorization", "Bearer injected")); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	tc := connectThenTLS(t, routerAddr, "probe.test:443", "probe.test", "\r\n", ca)
	resp := requestOver(t, tc, "GET / HTTP/1.1\r\nHost: probe.test\r\n\r\n")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != "auth=Bearer injected" {
		t.Fatalf("body = %q, want the injected credential", body)
	}
}

// Padding must not be mistaken for payload: a tunnel that really does open with
// CRLFs still carries them.
func TestConnectPaddingDoesNotEatPayload(t *testing.T) {
	echo, _ := tcpEcho(t, "raw")

	ca := generateTestCA(t)
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := p.ForwardTo("raw.test:9999", echo); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	conn, err := net.DialTimeout("tcp", p.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Two CRLFs of padding, then a payload that itself begins with one.
	fmt.Fprint(conn, "CONNECT raw.test:9999 HTTP/1.1\r\nHost: raw.test:9999\r\n\r\n\r\n\r\n")
	br := bufio.NewReader(conn)
	if _, err := http.ReadResponse(br, nil); err != nil {
		t.Fatalf("CONNECT: %v", err)
	}

	fmt.Fprint(conn, "\r\n\r\n\r\n\r\n\r\n\r\n\r\nPAYLOAD")
	conn.(*net.TCPConn).CloseWrite()
	answer, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.HasSuffix(string(answer), "PAYLOAD") {
		t.Fatalf("target received %q, want it to end in PAYLOAD", answer)
	}
}

// 2. Alt-Svc advertises another way to reach the same origin — over HTTP/3, on
// UDP, which this proxy neither terminates nor routes. A client that takes the
// offer leaves the tunnel entirely: no interception, no injected credential, no
// error anywhere. mitmproxy rewrites the header to point at itself and calls
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

	t.Run("through the sandbox router", func(t *testing.T) {
		router := vtunnel.NewServer()
		defer router.Close()
		if err := router.StartProxy("127.0.0.1:0"); err != nil {
			t.Fatalf("StartProxy: %v", err)
		}
		proxyURL, _ := url.Parse("http://" + router.Router().Addr().String())
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
			t.Fatalf("client saw Alt-Svc %q through the router", got)
		}
	})
}

// 3. An informational response is a real answer that arrives before the real
// answer: 103 Early Hints tells a browser what to start fetching while the
// upstream is still thinking. RoundTrip does not surface them, so they were
// dropped — the client got the 200 and none of the hints.
func TestInformationalResponsesReachTheClient(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</style.css>; rel=preload; as=style")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("Link")
		fmt.Fprint(w, "done")
	}))
	defer backend.Close()

	addr, ca := gapProxy(t, backend.Listener.Addr().String())
	tc := connectThenTLS(t, addr, "probe.test:443", "probe.test", "", ca)

	if _, err := io.WriteString(tc, "GET / HTTP/1.1\r\nHost: probe.test\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}

	br := bufio.NewReader(tc)
	early, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read first response: %v", err)
	}
	if early.StatusCode != http.StatusEarlyHints {
		t.Fatalf("first response = %s, want 103 Early Hints", early.Status)
	}
	if got := early.Header.Get("Link"); got != "</style.css>; rel=preload; as=style" {
		t.Fatalf("103 Link = %q", got)
	}

	final, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read final response: %v", err)
	}
	body, _ := io.ReadAll(final.Body)
	final.Body.Close()
	if final.StatusCode != http.StatusOK || string(body) != "done" {
		t.Fatalf("final response = %s %q", final.Status, body)
	}
	// The hint's headers belong to the hint, not to the answer.
	if got := final.Header.Get("Link"); got != "" {
		t.Fatalf("the 200 carried the 103's Link header (%q)", got)
	}
}

// 4. HTTP/1.0 has no Host header, and net/http passes such a request to the
// handler as it stands. Comparing that empty Host against the CONNECT authority
// made every HTTP/1.0 request inside an intercepted tunnel a 421 — the check is
// right and necessary, it just had nothing to compare.
func TestHTTP10WithoutHostIsServedInsideMITM(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "auth=%s host=%s", r.Header.Get("Authorization"), r.Host)
	}))
	defer backend.Close()

	addr, ca := gapProxy(t, backend.Listener.Addr().String())
	tc := connectThenTLS(t, addr, "probe.test:443", "probe.test", "", ca)

	resp := requestOver(t, tc, "GET / HTTP/1.0\r\n\r\n")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %s, want 200: an HTTP/1.0 request has no Host to match, and "+
			"the authority it arrived on is the answer", resp.Status)
	}
	if !strings.Contains(string(body), "auth=Bearer injected") {
		t.Fatalf("body = %q, want the injected credential", body)
	}
	if !strings.Contains(string(body), "host=probe.test") {
		t.Fatalf("body = %q, want the CONNECT authority filled in as the Host", body)
	}
}

// The guard it sits next to still holds: a request aimed at another virtual
// host is refused, because that is how a sandbox would point an injected
// credential somewhere it was never meant to go.
func TestMismatchedHostInsideMITMIsStillRefused(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "reached")
	}))
	defer backend.Close()

	addr, ca := gapProxy(t, backend.Listener.Addr().String())
	tc := connectThenTLS(t, addr, "probe.test:443", "probe.test", "", ca)

	resp := requestOver(t, tc, "GET / HTTP/1.1\r\nHost: other.test\r\n\r\n")
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status = %s, want 421", resp.Status)
	}
}
