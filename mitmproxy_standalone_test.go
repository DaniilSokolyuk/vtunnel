package vtunnel_test

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
	"sync"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

// MITMProxy depends on neither Server nor Client, so it can be used on its own
// as an intercepting forward proxy with no tunnel anywhere in sight. Start opens
// the listener itself; nothing else has to be wired up.
func TestMITMProxyStandalone(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "seen:%s", r.Header.Get("Authorization"))
	}))
	defer backend.Close()

	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "direct")
	}))
	defer direct.Close()

	// The whole setup: a CA, a proxy, one mapping.
	caPEM, err := vtunnel.GenerateCA("standalone test CA")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	ca, err := vtunnel.LoadCA(caPEM)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxy.Close()

	proxy.ForwardTo("api.test:443", backend.Listener.Addr().String(),
		vtunnel.WithHeader("Authorization", "Bearer injected"))

	// Start picked the port; Addr reports it.
	if proxy.Addr() == nil {
		t.Fatal("Addr is nil after Start")
	}
	client := proxyClient(t, proxy.Addr().String(), ca)

	// Mapped: intercepted, header injected.
	if got := readAll(t, client, "https://api.test/hello"); got != "seen:Bearer injected" {
		t.Fatalf("mapped = %q, want the injected credential", got)
	}

	// Unmapped: dialled straight through, no mapping needed.
	if got := readAll(t, client, direct.URL); got != "direct" {
		t.Fatalf("unmapped = %q, want direct", got)
	}
}

// Without a CA the same proxy still routes, it just never decrypts — so a
// mapped HTTPS domain is piped through to its target untouched.
func TestMITMProxyStandaloneWithoutCA(t *testing.T) {
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "backend")
	}))
	backend.StartTLS()
	defer backend.Close()

	proxy := vtunnel.NewMITMProxy()
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxy.Close()

	proxy.ForwardTo("plain.test:443", backend.Listener.Addr().String())

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(mustParseURL(t, "http://"+proxy.Addr().String())),
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}

	resp, err := client.Get("https://plain.test/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	// The certificate is the backend's own: nothing was terminated in between.
	backendCert, err := x509.ParseCertificate(backend.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse backend cert: %v", err)
	}
	if !resp.TLS.PeerCertificates[0].Equal(backendCert) {
		t.Fatal("a proxy with no CA must not terminate TLS")
	}
}

// --- helpers ---

func proxyClient(t *testing.T, proxyAddr string, ca tls.Certificate) *http.Client {
	t.Helper()

	caLeaf, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caLeaf)

	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(t, "http://"+proxyAddr)),
			// The generated leaf really does chain to the CA — no skipping verify.
			TLSClientConfig:   &tls.Config{RootCAs: roots},
			DisableKeepAlives: true,
		},
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", raw, err)
	}
	return u
}

func readAll(t *testing.T, c *http.Client, rawURL string) string {
	t.Helper()
	resp, err := c.Get(rawURL)
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

// A proxy may be handed an absolute-form request instead of a CONNECT —
// `GET https://host/path HTTP/1.1` straight at the proxy port. It is unusual,
// because a client that wants TLS normally tunnels, but it is legal and some
// tools do it.
//
// The scheme in that URL is the client saying which protocol it wants spoken to
// the origin. Reading only the route and not the scheme sent the request to
// port 443 in the clear — carrying whatever credential the client had attached
// to it, in a request it believed it had asked to encrypt.
func TestAbsoluteFormHTTPSReachesTheOriginOverTLS(t *testing.T) {
	var mu sync.Mutex
	var firstByte byte
	var sawCleartext bool

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				head := make([]byte, 512)
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, _ := conn.Read(head)
				mu.Lock()
				if n > 0 && firstByte == 0 {
					firstByte = head[0]
					sawCleartext = strings.Contains(string(head[:n]), "client-token")
				}
				mu.Unlock()
			}()
		}
	}()

	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(generateTestCA(t)))
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	conn, err := net.DialTimeout("tcp", p.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	fmt.Fprintf(conn, "GET https://%s/secret HTTP/1.1\r\nHost: %s\r\n"+
		"Authorization: Bearer client-token\r\n\r\n", ln.Addr(), ln.Addr())
	if resp, err := http.ReadResponse(bufio.NewReader(conn), nil); err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if sawCleartext {
		t.Fatal("the client's credential went to the origin in cleartext, on a request " +
			"whose URL asked for https")
	}
	if firstByte != 0x16 {
		t.Fatalf("first byte on the wire = %#x, want a TLS handshake record (0x16)", firstByte)
	}
}
