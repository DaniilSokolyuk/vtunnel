package vtunnel

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

// peekTimeout bounds the wait for the client's first byte and is cleared once
// the tunnel kind is known — after which the TLS handshake read the rest of the
// ClientHello with no deadline at all. A client that sends a record header and
// then stops held a goroutine and a descriptor for as long as the process lived.
func TestMITMHandshakeHasADeadline(t *testing.T) {
	prev := mitmHandshakeTimeout
	mitmHandshakeTimeout = 200 * time.Millisecond
	t.Cleanup(func() { mitmHandshakeTimeout = prev })

	proxy, proxyAddr, _ := startCoverageProxy(t, nil)
	proxy.ForwardTo("slowhello.test:443", "127.0.0.1:1")

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	fmt.Fprint(conn, "CONNECT slowhello.test:443 HTTP/1.1\r\nHost: slowhello.test:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	resp.Body.Close()

	// Enough to look like the start of a TLS record, then silence.
	if _, err := conn.Write([]byte{0x16, 0x03, 0x01}); err != nil {
		t.Fatalf("write: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("the proxy answered a handshake that was never completed")
	}
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Fatalf("the connection was still open after %v; the handshake has no deadline", elapsed)
	}
}
