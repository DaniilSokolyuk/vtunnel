package vtunnel

// Every blocking read on a peer that may simply stop talking needs an upper
// bound, or one unresponsive host turns into goroutines and file descriptors
// accumulating with nothing reported. These cover the two that had none.

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

// dialTimeout bounds only the dial to the chained proxy. After the CONNECT line
// was written, reading the answer blocked forever, so a controlplane that
// accepts TCP and then goes quiet — mid-reconnect, swapped out, a wedged hop —
// pinned one goroutine and two sockets per request from the sandbox.
func TestRouterChainedConnectHasAReplyDeadline(t *testing.T) {
	prev := connectReplyTimeout
	connectReplyTimeout = 200 * time.Millisecond
	t.Cleanup(func() { connectReplyTimeout = prev })

	// A "controlplane" that accepts and never answers.
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer silent.Close()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()

	router := newRouter()
	if err := router.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer router.Close()
	router.SetRoutes(silent.Addr().(*net.TCPAddr).Port, []string{"quiet.test"})

	conn, err := net.DialTimeout("tcp", router.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial router: %v", err)
	}
	defer conn.Close()

	fmt.Fprint(conn, "CONNECT quiet.test:443 HTTP/1.1\r\nHost: quiet.test:443\r\n\r\n")

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("the router never answered in %v: the chained CONNECT has no read deadline (%v)", elapsed, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("the router reported a tunnel to a proxy that never accepted it")
	}
	if elapsed >= 5*time.Second {
		t.Fatalf("the router took %v to give up", elapsed)
	}
}
