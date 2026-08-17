package vtunnel_test

// Cleartext HTTP inside a CONNECT tunnel.
//
// A client that reaches the proxy through SOCKS5 opens every connection with
// CONNECT, whatever it then speaks — so `curl http://api.corp/` arrives as
// CONNECT api.corp:80 followed by an ordinary HTTP/1.1 request. The same shape
// turns up with HTTPS_PROXY when a client tunnels port 80.
//
// For a route served in process this used to be dropped: the connection was
// closed and the log said "this is not HTTP" about a request that plainly was.

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/vivid-money/vtunnel"
)

// connectTo opens a CONNECT tunnel to authority through the proxy at addr and
// returns the tunnelled connection with its reader.
func connectTo(t *testing.T, addr, authority string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("CONNECT %s: %v", authority, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT %s: %s", authority, resp.Status)
	}
	return conn, br
}

func TestHandlerRouteServesCleartextHTTPInsideConnect(t *testing.T) {
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(generateTestCA(t)))
	p.Handle("api.corp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "handled %s", r.URL.Path)
	}))
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	conn, br := connectTo(t, p.Addr().String(), "api.corp:80")

	fmt.Fprint(conn, "GET /hello HTTP/1.1\r\nHost: api.corp\r\n\r\n")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("the handler route dropped a cleartext HTTP request tunnelled through "+
			"CONNECT, which is how every SOCKS5 client reaches it: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != "handled /hello" {
		t.Fatalf("body = %q, want the handler's answer", body)
	}
}

// Keep-alive works too: the tunnel carries a connection, not one request.
func TestHandlerRouteServesSeveralCleartextRequests(t *testing.T) {
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(generateTestCA(t)))
	p.Handle("api.corp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "handled %s", r.URL.Path)
	}))
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	conn, br := connectTo(t, p.Addr().String(), "api.corp:80")

	for _, path := range []string{"/one", "/two"} {
		fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: api.corp\r\n\r\n", path)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "handled "+path {
			t.Fatalf("%s: body = %q", path, body)
		}
	}
}

// What is not HTTP still is not: a handler route has nowhere to pipe to, so a
// connection carrying something else is closed rather than guessed at.
func TestHandlerRouteStillRefusesNonHTTP(t *testing.T) {
	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(generateTestCA(t)))
	// Registered on the port the test uses: a bare domain covers :80 and :443.
	p.Handle("api.corp:5432", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "handled")
	}))
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	conn, br := connectTo(t, p.Addr().String(), "api.corp:5432")

	// A postgres startup packet: a length, then a protocol version.
	conn.Write([]byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f})
	if _, err := io.ReadAll(br); err != nil {
		t.Fatalf("read: %v", err)
	}
	// Reading to EOF is the assertion: nothing answered, and nothing hung.
}

// The whole way round, as an application in a sandbox sees it: plain HTTP over
// SOCKS5 into a route served in process on the controlplane.
func TestSocks5CleartextHTTPReachesAHandlerRoute(t *testing.T) {
	ts, server := startTunnelServer(t)
	defer ts.Close()

	egressAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := server.StartProxy(egressAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	client := vtunnel.NewClient(wsURL(ts), vtunnel.WithMitm(generateTestCA(t)))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	client.Proxy().Handle("api.corp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "in process: %s", r.URL.Path)
	}))
	time.Sleep(150 * time.Millisecond)

	dialer, err := proxy.SOCKS5("tcp", egressAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("socks5 dialer: %v", err)
	}
	httpClient := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Dial: dialer.Dial},
	}

	resp, err := httpClient.Get("http://api.corp/thing")
	if err != nil {
		t.Fatalf("GET through socks5: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "in process: /thing" {
		t.Fatalf("body = %q, want the in-process handler's answer", body)
	}
}

// Sorting a tunnel by its first bytes must not wait for bytes that are not
// coming.
//
// Deciding whether a connection carries h2c meant peeking the whole 24-byte
// client preface, and a peek waits. Every protocol that opens with a short
// packet and then expects the server to speak — postgres sends eight bytes,
// redis six — stalled for the whole peek timeout before a single byte moved.
// Nothing noticed while HTTPS was the only way in; SOCKS5 makes it the ordinary
// case.
func TestShortNonHTTPOpeningIsNotStalled(t *testing.T) {
	// A "database": answers as soon as it is greeted, and does not wait for EOF.
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
				head := make([]byte, 8)
				if _, err := io.ReadFull(conn, head); err != nil {
					return
				}
				conn.Write([]byte("HELLO"))
			}()
		}
	}()

	p := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(generateTestCA(t)))
	if err := p.ForwardTo("db.corp:5432", ln.Addr().String()); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	conn, br := connectTo(t, p.Addr().String(), "db.corp:5432")

	start := time.Now()
	// A postgres SSLRequest: eight bytes, then the client waits.
	conn.Write([]byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f})

	answer := make([]byte, 5)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(br, answer); err != nil {
		t.Fatalf("no answer in %v: the proxy is still waiting to classify a connection "+
			"whose opening bytes are all it is ever going to send (%v)", time.Since(start), err)
	}
	if string(answer) != "HELLO" {
		t.Fatalf("answer = %q", answer)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("the answer took %v to come back", elapsed)
	}
}
