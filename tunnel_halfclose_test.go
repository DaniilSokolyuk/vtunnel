package vtunnel_test

// Half-close through the tunnel.
//
// A great many clients say "I am done asking" by shutting down their write side
// and then reading the answer: curl --http1.0, git over a plain forward, any
// request/response protocol that frames the request by end-of-stream. The FIN
// they send has to reach the target as a FIN and nothing more — if it is
// delivered as "this connection is over", the response dies in flight and the
// caller sees a truncated or empty body with no error anywhere.
//
// The sandbox-side egress proxy already sends half-close deliberately: dualStream
// calls CloseWrite on the tunnel socket as soon as the application has finished
// its request. So this is not an exotic path, it is the ordinary one.

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

// startTunnelServerWithProtocol is startTunnelServer for a chosen session
// backend, so the same behaviour can be asserted on every one of them.
func startTunnelServerWithProtocol(t *testing.T, p vtunnel.Protocol) (*httptest.Server, *vtunnel.Server) {
	t.Helper()
	server := vtunnel.NewServer(vtunnel.WithServerProtocol(p))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Upgrade error: %v", err)
			return
		}
		defer conn.Close()
		server.HandleWebSocket(conn)
	}))
	return ts, server
}

// echoAfterEOF answers only once the request has ended, which is what makes it
// a half-close test: it cannot reply until it has seen the FIN, and it can only
// see the FIN if the tunnel forwarded one instead of tearing the stream down.
func echoAfterEOF(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				req, err := io.ReadAll(conn)
				if err != nil {
					return
				}
				fmt.Fprintf(conn, "RESPONSE(%s)", req)
			}()
		}
	}()
	return ln
}

func TestTunnelForwardsHalfClose(t *testing.T) {
	for _, protocol := range []vtunnel.Protocol{vtunnel.ProtocolSSH, vtunnel.ProtocolYamux} {
		t.Run(string(protocol), func(t *testing.T) {
			target := echoAfterEOF(t)
			defer target.Close()

			ts, _ := startTunnelServerWithProtocol(t, protocol)
			defer ts.Close()

			client := vtunnel.NewClient(wsURL(ts), vtunnel.WithProtocol(protocol))
			if err := client.Connect(); err != nil {
				t.Fatalf("Connect: %v", err)
			}
			defer client.Close()

			port := freePort(t)
			if err := client.Listen(port, target.Addr().String()); err != nil {
				t.Fatalf("Listen: %v", err)
			}

			conn := dialSandboxPort(t, port)
			defer conn.Close()

			if _, err := conn.Write([]byte("REQUEST")); err != nil {
				t.Fatalf("write: %v", err)
			}
			// "I am done asking." Nothing more, and certainly not "I am done
			// listening".
			if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatalf("CloseWrite: %v", err)
			}

			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			got, err := io.ReadAll(conn)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			if string(got) != "RESPONSE(REQUEST)" {
				t.Fatalf("response = %q, want %q: the half-close was delivered as a full "+
					"close, so the target's answer never made it back", got, "RESPONSE(REQUEST)")
			}
		})
	}
}

// The other direction of the same property: the target finishing its answer
// must not cut off a request the application is still writing. This is what a
// naive "CloseWrite on the destination" fix gets wrong when it also closes the
// source.
func TestTunnelForwardsHalfCloseFromTheTargetSide(t *testing.T) {
	// Says its piece immediately, then closes its write side and keeps reading.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("GREETING"))
		conn.(*net.TCPConn).CloseWrite()
		rest, _ := io.ReadAll(conn)
		received <- string(rest)
	}()

	ts, _ := startTunnelServer(t)
	defer ts.Close()

	client := vtunnel.NewClient(wsURL(ts))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	port := freePort(t)
	if err := client.Listen(port, ln.Addr().String()); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	conn := dialSandboxPort(t, port)
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	greeting := make([]byte, len("GREETING"))
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// The target has half-closed; this side is still allowed to talk.
	if _, err := conn.Write([]byte("LATE")); err != nil {
		t.Fatalf("write after the target half-closed: %v", err)
	}
	conn.(*net.TCPConn).CloseWrite()

	select {
	case got := <-received:
		if got != "LATE" {
			t.Fatalf("target received %q, want %q: the target's half-close tore down the "+
				"other direction with it", got, "LATE")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the target never received what was written after it half-closed")
	}
}

// dialSandboxPort connects to a port the sandbox opened, retrying briefly: the
// listener is created while the listen request is being answered.
func dialSandboxPort(t *testing.T, port int) net.Conn {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			return conn
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial sandbox port %d: %v", port, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
