package vtunnel_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/DaniilSokolyuk/vtunnel"
)

func TestProxyPlainHTTPMapped(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "proxy-ok")
	}))
	defer backend.Close()

	server := vtunnel.NewServer()
	proxyPort := freePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if err := server.StartProxy(proxyAddr); err != nil {
		t.Fatalf("StartProxy error: %v", err)
	}
	defer server.CloseProxy()

	server.SetDomainMapping("example.test:80", backend.Listener.Addr().String())

	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("Proxy URL parse error: %v", err)
	}

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Get("http://example.test/hello")
	if err != nil {
		t.Fatalf("Proxy GET error: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "proxy-ok" {
		t.Fatalf("Unexpected body: %q", string(body))
	}
}

func TestProxyConnectMapped(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Echo listen error: %v", err)
	}
	defer echoLn.Close()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	server := vtunnel.NewServer()
	proxyPort := freePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if err := server.StartProxy(proxyAddr); err != nil {
		t.Fatalf("StartProxy error: %v", err)
	}
	defer server.CloseProxy()

	server.SetDomainMapping("example.test:443", echoLn.Addr().String())

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial proxy error: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	_, err = fmt.Fprintf(conn, "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
	if err != nil {
		t.Fatalf("CONNECT write error: %v", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("CONNECT read status error: %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("Unexpected CONNECT status: %q", statusLine)
	}

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("CONNECT read headers error: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	payload := []byte("proxy-echo")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Tunnel write error: %v", err)
	}

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("Tunnel read error: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("Unexpected echo: %q", string(buf))
	}
}
