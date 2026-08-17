package vtunnel

// What EgressProxy.Start accepts, and what each form serves.
//
// The address may carry a scheme, the way gost and glider spell it, because a
// sandbox that wants only one of the two protocols should not need a second
// flag to say so. No scheme means both: one port for HTTP_PROXY and ALL_PROXY
// together is the case worth making shortest.

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseProxyScheme(t *testing.T) {
	cases := []struct {
		in       string
		wantMode proxyMode
		wantAddr string
		wantErr  bool
	}{
		{in: "127.0.0.1:9090", wantMode: proxyMixed, wantAddr: "127.0.0.1:9090"},
		{in: ":9090", wantMode: proxyMixed, wantAddr: ":9090"},
		{in: "mixed://127.0.0.1:9090", wantMode: proxyMixed, wantAddr: "127.0.0.1:9090"},
		{in: "mixed://:8080", wantMode: proxyMixed, wantAddr: ":8080"},
		{in: "http://127.0.0.1:8080", wantMode: proxyHTTP, wantAddr: "127.0.0.1:8080"},
		{in: "socks5://127.0.0.1:1080", wantMode: proxySocks5, wantAddr: "127.0.0.1:1080"},
		{in: "[::1]:9090", wantMode: proxyMixed, wantAddr: "[::1]:9090"},
		{in: "socks5://127.0.0.1", wantErr: true}, // no port
		{in: "gopher://127.0.0.1:70", wantErr: true},
		{in: "", wantErr: true},
	}

	for _, tc := range cases {
		mode, addr, err := parseProxyScheme(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseProxyScheme(%q) = (%v, %q, nil), want an error", tc.in, mode, addr)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseProxyScheme(%q): %v", tc.in, err)
			continue
		}
		if mode != tc.wantMode || addr != tc.wantAddr {
			t.Errorf("parseProxyScheme(%q) = (%v, %q), want (%v, %q)",
				tc.in, mode, addr, tc.wantMode, tc.wantAddr)
		}
	}
}

// socks5://: an HTTP client that wanders in is hung up on rather than served,
// because the operator said what this port is for.
func TestEgressSocks5OnlyRefusesHTTP(t *testing.T) {
	egress := newEgressProxy()
	if err := egress.Start("socks5://127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer egress.Close()

	conn, err := net.DialTimeout("tcp", egress.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatalf("read: %v", err)
	}
	// Reading to EOF is the assertion: a served connection would have answered.

	// And SOCKS5 still works on it.
	if greetSocks5(t, egress.Addr().String()) != MethodNoAuthAccepted {
		t.Fatal("the SOCKS5-only listener did not answer a SOCKS5 greeting")
	}
}

// http://: no sniffing, and a SOCKS5 greeting is answered by the HTTP server
// with what it makes of it — the point being that the operator gets what they
// asked for and nothing else is listening.
func TestEgressHTTPOnlyDoesNotSpeakSocks5(t *testing.T) {
	egress := newEgressProxy()
	if err := egress.Start("http://127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer egress.Close()

	conn, err := net.DialTimeout("tcp", egress.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	// An HTTP server makes nothing of those three bytes and waits for the rest
	// of a request line it is never getting, until its header deadline. So a
	// read timeout here is the expected outcome; what must not happen is a
	// SOCKS5 method selection coming back.
	conn.SetReadDeadline(time.Now().Add(time.Second))
	answer := make([]byte, 2)
	n, err := io.ReadFull(conn, answer)
	if err == nil && answer[0] == 0x05 {
		t.Fatal("an http:// listener answered a SOCKS5 greeting")
	}
	if n > 0 && !strings.HasPrefix(string(answer[:n]), "HT") {
		t.Fatalf("answer = % x, want an HTTP response or nothing", answer[:n])
	}
}

// A bad scheme is refused at Start, before a port is opened.
func TestEgressStartRejectsUnknownScheme(t *testing.T) {
	egress := newEgressProxy()
	if err := egress.Start("gopher://127.0.0.1:0"); err == nil {
		egress.Close()
		t.Fatal("Start accepted a scheme it cannot serve")
	}
	if egress.Addr() != nil {
		t.Fatal("Start opened a listener for an address it then refused")
	}
}

// MethodNoAuthAccepted is what a well-formed greeting gets back.
const MethodNoAuthAccepted = 0x00

func greetSocks5(t *testing.T, addr string) byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(bufio.NewReader(conn), reply); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if reply[0] != 0x05 {
		t.Fatalf("method selection = % x, want a SOCKS5 answer", reply)
	}
	return reply[1]
}
