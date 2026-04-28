package vtunnel_test

import (
	"bufio"
	"crypto/tls"
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

// TestProxyWildcardMatching drives the full CONNECT path through a real proxy
// for a table of wildcard scenarios. A mapped target (open listener) returns
// 200; an unmapped request falls through to direct-dial against the authority,
// which for `.test` TLDs fails (DNS miss → 502). So `wantHit` ⇔ CONNECT
// returned 200.
func TestProxyWildcardMatching(t *testing.T) {
	mapped := openDrainListener(t)
	defer mapped.Close()
	mappedAddr := mapped.Addr().String()

	other := openDrainListener(t)
	defer other.Close()
	otherAddr := other.Addr().String()

	cases := []struct {
		name     string
		mappings map[string]string
		host     string // CONNECT authority
		wantHit  bool
	}{
		{
			name:     "leftmost single-label hit",
			mappings: map[string]string{"*.example.test:443": mappedAddr},
			host:     "a.example.test:443",
			wantHit:  true,
		},
		{
			name:     "leftmost multi-label hit",
			mappings: map[string]string{"*.example.test:443": mappedAddr},
			host:     "a.b.example.test:443",
			wantHit:  true,
		},
		{
			name:     "leftmost apex miss",
			mappings: map[string]string{"*.example.test:443": mappedAddr},
			host:     "example.test:443",
			wantHit:  false,
		},
		{
			name:     "leftmost port mismatch miss",
			mappings: map[string]string{"*.example.test:443": mappedAddr},
			host:     "a.example.test:80",
			wantHit:  false,
		},
		{
			name:     "rightmost single-label hit",
			mappings: map[string]string{"mail.*:443": mappedAddr},
			host:     "mail.example.test:443",
			wantHit:  true,
		},
		{
			name:     "rightmost multi-label hit",
			mappings: map[string]string{"mail.*:443": mappedAddr},
			host:     "mail.foo.example.test:443",
			wantHit:  true,
		},
		{
			name:     "rightmost prefix-without-dot miss",
			mappings: map[string]string{"mail.*:443": mappedAddr},
			host:     "mailbox.example.test:443",
			wantHit:  false,
		},
		{
			name:     "rightmost bare-prefix miss",
			mappings: map[string]string{"mail.*:443": mappedAddr},
			host:     "mail:443",
			wantHit:  false,
		},
		{
			name: "exact wins over wildcard",
			mappings: map[string]string{
				"*.example.test:443":     otherAddr,
				"exact.example.test:443": mappedAddr,
			},
			host:    "exact.example.test:443",
			wantHit: true,
		},
		{
			name: "leftmost wins over rightmost",
			mappings: map[string]string{
				"*.example.test:443": mappedAddr,
				"mail.*:443":         otherAddr,
			},
			host:    "mail.example.test:443",
			wantHit: true,
		},
		{
			name: "longer leftmost wins over shorter",
			mappings: map[string]string{
				"*.test:443":         otherAddr,
				"*.example.test:443": mappedAddr,
			},
			host:    "a.example.test:443",
			wantHit: true,
		},
		{
			name: "longer rightmost wins over shorter",
			mappings: map[string]string{
				"foo.*:443":     otherAddr,
				"foo.bar.*:443": mappedAddr,
			},
			host:    "foo.bar.example.test:443",
			wantHit: true,
		},
		{
			name:     "middle asterisk is not a wildcard",
			mappings: map[string]string{"a.*.example.test:443": mappedAddr},
			host:     "a.b.example.test:443",
			wantHit:  false,
		},
		{
			name:     "partial-label asterisk is not a wildcard",
			mappings: map[string]string{"w*.example.test:443": mappedAddr},
			host:     "www.example.test:443",
			wantHit:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, proxyAddr := startProxyForTest(t)

			for pattern, tgt := range tc.mappings {
				server.SetDomainMapping(pattern, tgt)
			}

			got200 := connectReturns200(t, proxyAddr, tc.host)

			if tc.wantHit && !got200 {
				t.Fatalf("Expected 200 (mapped hit), got non-200")
			}
			if !tc.wantHit && got200 {
				t.Fatalf("Expected non-200 (miss), but CONNECT succeeded")
			}
		})
	}
}

// TestProxyWildcardPriorityPicksCorrectTarget verifies that when multiple
// wildcard patterns could match, the priority rule picks the right *target*
// (not just "any 200"). Uses HTTP backends that echo a tag in the body so we
// can tell which one actually served the request.
func TestProxyWildcardPriorityPicksCorrectTarget(t *testing.T) {
	cases := []struct {
		name     string
		host     string
		mappings func(winner, loser string) map[string]string
	}{
		{
			name: "exact beats leftmost",
			host: "exact.example.test",
			mappings: func(w, l string) map[string]string {
				return map[string]string{
					"*.example.test:80":     l,
					"exact.example.test:80": w,
				}
			},
		},
		{
			name: "leftmost beats rightmost",
			host: "mail.example.test",
			mappings: func(w, l string) map[string]string {
				return map[string]string{
					"*.example.test:80": w,
					"mail.*:80":         l,
				}
			},
		},
		{
			name: "longer leftmost beats shorter",
			host: "a.example.test",
			mappings: func(w, l string) map[string]string {
				return map[string]string{
					"*.test:80":         l,
					"*.example.test:80": w,
				}
			},
		},
		{
			name: "longer rightmost beats shorter",
			host: "foo.bar.example.test",
			mappings: func(w, l string) map[string]string {
				return map[string]string{
					"foo.*:80":     l,
					"foo.bar.*:80": w,
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			winner := tagBackend("winner")
			defer winner.Close()
			loser := tagBackend("loser")
			defer loser.Close()

			server, proxyAddr := startProxyForTest(t)
			for pattern, target := range tc.mappings(winner.Listener.Addr().String(), loser.Listener.Addr().String()) {
				server.SetDomainMapping(pattern, target)
			}

			body := httpViaProxy(t, proxyAddr, tc.host)
			if body != "winner" {
				t.Fatalf("Expected body 'winner' (correct target picked), got %q", body)
			}
		})
	}
}

// TestProxyWildcardMitm verifies the MITM path issues a leaf cert for the
// concrete hostname matched by a wildcard pattern — not the pattern itself —
// even across multiple labels.
func TestProxyWildcardMitm(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "wildcard-mitm-ok")
	}))
	defer backend.Close()

	ca := generateTestCA(t)
	server := vtunnel.NewServer(vtunnel.WithProxyMitmCA(ca))
	proxyPort := freePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if err := server.StartProxy(proxyAddr); err != nil {
		t.Fatalf("StartProxy error: %v", err)
	}
	defer server.CloseProxy()

	server.SetDomainMapping("*.secure.test:443", backend.Listener.Addr().String())

	proxyConn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial proxy: %v", err)
	}
	defer proxyConn.Close()
	proxyConn.SetDeadline(time.Now().Add(5 * time.Second))

	fmt.Fprintf(proxyConn, "CONNECT a.b.secure.test:443 HTTP/1.1\r\nHost: a.b.secure.test:443\r\n\r\n")
	br := bufio.NewReader(proxyConn)
	status, _ := br.ReadString('\n')
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT failed: %s", status)
	}
	for {
		line, _ := br.ReadString('\n')
		if line == "\r\n" {
			break
		}
	}

	tunnelConn := newBufConn(proxyConn, br)
	tlsConn := tls.Client(tunnelConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "a.b.secure.test",
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	defer tlsConn.Close()

	leaf := tlsConn.ConnectionState().PeerCertificates[0]
	if leaf.Subject.CommonName != "a.b.secure.test" {
		t.Fatalf("Leaf CN = %q, want a.b.secure.test", leaf.Subject.CommonName)
	}
	foundSAN := false
	for _, name := range leaf.DNSNames {
		if name == "a.b.secure.test" {
			foundSAN = true
			break
		}
	}
	if !foundSAN {
		t.Fatalf("Leaf DNSNames = %v, want to include a.b.secure.test", leaf.DNSNames)
	}
}

// --- helpers ---

// openDrainListener accepts TCP connections and closes them immediately.
// Used as a "target reached" sentinel for CONNECT tests.
func openDrainListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen error: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	return ln
}

func tagBackend(tag string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, tag)
	}))
}

func startProxyForTest(t *testing.T) (*vtunnel.Server, string) {
	t.Helper()
	s := vtunnel.NewServer()
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := s.StartProxy(addr); err != nil {
		t.Fatalf("StartProxy error: %v", err)
	}
	t.Cleanup(func() { s.CloseProxy() })
	return s, addr
}

func connectReturns200(t *testing.T, proxyAddr, host string) bool {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial proxy error: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		return false
	}
	return strings.Contains(status, "200")
}

func httpViaProxy(t *testing.T, proxyAddr, host string) string {
	t.Helper()
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("Parse proxy URL: %v", err)
	}
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp, err := client.Get("http://" + host + "/")
	if err != nil {
		t.Fatalf("GET via proxy error: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
