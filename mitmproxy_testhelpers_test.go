package vtunnel

// Helpers shared by the internal proxy tests.

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"context"

	"golang.org/x/net/http2"
)

func startCoverageProxy(t *testing.T, setup func(*MITMProxy)) (*MITMProxy, string, tls.Certificate) {
	t.Helper()

	blob, err := GenerateCA("coverage CA")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	ca, err := LoadCA(blob)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	proxy := NewMITMProxy(WithMitmCA(ca))
	if setup != nil {
		setup(proxy)
	}
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(proxy.Close)
	return proxy, proxy.Addr().String(), ca
}

func coverageClient(proxyAddr string, ca tls.Certificate, disableKeepAlives bool) *http.Client {
	leaf, _ := x509.ParseCertificate(ca.Certificate[0])
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
			TLSClientConfig:   &tls.Config{RootCAs: roots},
			DisableKeepAlives: disableKeepAlives,
		},
	}
}

func getBody(t *testing.T, c *http.Client, rawURL string) string {
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

// startRawEchoListener serves a plain TCP echo, so a CONNECT tunnel can be
// checked without any protocol on top of it. Returns its address.
func startRawEchoListener(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
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
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// h2ConnectTunnel opens a CONNECT tunnel over HTTP/2 (h2c) and returns it as a
// reader/writer pair joined into one stream.
func h2ConnectTunnel(t *testing.T, proxyAddr, target string) io.ReadWriter {
	t.Helper()

	transport := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return net.Dial(network, proxyAddr)
		},
	}

	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodConnect, "http://"+target, pr)
	if err != nil {
		t.Fatalf("new CONNECT: %v", err)
	}
	req.Host = target

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("HTTP/2 CONNECT: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close(); pw.Close() })

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}
	return &pipeStream{r: resp.Body, w: pw}
}

type pipeStream struct {
	r io.Reader
	w io.Writer
}

func (s *pipeStream) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *pipeStream) Write(p []byte) (int, error) { return s.w.Write(p) }

func assertEchoTunnel(t *testing.T, conn io.ReadWriter, payload string) {
	t.Helper()

	go func() { io.WriteString(conn, payload) }()

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if got := string(buf); got != payload {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
	_ = strings.TrimSpace(payload)
}
