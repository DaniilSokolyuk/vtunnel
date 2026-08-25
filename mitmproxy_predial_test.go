package vtunnel

// The ALPN mirroring design opens the upstream connection from inside the
// client's TLS handshake, before the client has proved anything at all. That is
// what makes the proxy able to offer the client exactly what the upstream
// negotiated — and it means a client that says ClientHello and then stops can
// make the proxy dial an internal service on its behalf.

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestPendingUpstreamDialsAreBounded(t *testing.T) {
	defer func(previous int) { maxPendingUpstreamDials = previous }(maxPendingUpstreamDials)
	maxPendingUpstreamDials = 4 // set for this test only

	// An upstream that accepts and then says nothing, so every pre-dial is
	// still outstanding when the next one starts.
	var accepted atomic.Int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	held := make(chan struct{})
	defer close(held)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer conn.Close()
				<-held
			}()
		}
	}()

	blob, err := GenerateCA("predial")
	if err != nil {
		t.Fatal(err)
	}
	ca, err := LoadCA(blob)
	if err != nil {
		t.Fatal(err)
	}

	p := NewMITMProxy(WithMitmCA(ca))
	if err := p.ForwardTo("api.corp", "tls://"+ln.Addr().String(), WithSNI("api.corp")); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	// Twenty clients that open a tunnel, start a handshake and then wait.
	for range 20 {
		go func() {
			conn, err := net.DialTimeout("tcp", p.Addr().String(), 2*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()
			fmt.Fprint(conn, "CONNECT api.corp:443 HTTP/1.1\r\nHost: api.corp:443\r\n\r\n")
			buf := make([]byte, 128)
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := conn.Read(buf); err != nil {
				return
			}
			tc := tls.Client(conn, &tls.Config{ServerName: "api.corp", InsecureSkipVerify: true}) //nolint:gosec // test
			tc.HandshakeContext(t.Context())
			<-held
		}()
	}

	time.Sleep(2 * time.Second)
	if n := accepted.Load(); int(n) > maxPendingUpstreamDials {
		t.Fatalf("%d upstream connections are open for handshakes nobody has completed; "+
			"the cap is %d — an unauthenticated client can make the proxy open as many "+
			"connections into the controlplane's network as it likes", n, maxPendingUpstreamDials)
	}
}
