package vtunnel_test

// The tunnel over each session protocol, and over a transport that is not a
// WebSocket. Both are the point of the split: what carries the bytes and what
// multiplexes them are separate choices, and the tunnel above works the same
// either way.

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

var protocols = []vtunnel.Protocol{
	vtunnel.ProtocolSSH,
	vtunnel.ProtocolYamux,
	vtunnel.ProtocolYamuxInsecure,
}

// startProtocolServer runs a vtunnel server over WebSocket speaking p.
func startProtocolServer(t *testing.T, p vtunnel.Protocol) *httptest.Server {
	t.Helper()
	server := vtunnel.NewServer(
		vtunnel.WithServerProtocol(p),
		vtunnel.WithServerSecret(secretA),
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		server.HandleWebSocket(conn)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// Every protocol carries a real forwarded connection end to end.
func TestTunnelOverEachProtocol(t *testing.T) {
	for _, p := range protocols {
		t.Run(string(p), func(t *testing.T) {
			ts := startProtocolServer(t, p)

			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("tunnelled"))
			}))
			defer backend.Close()

			client := vtunnel.NewClient(wsURL(ts),
				vtunnel.WithProtocol(p),
				vtunnel.WithSecret(secretA),
			)
			if err := client.Connect(); err != nil {
				t.Fatalf("Connect over %s: %v", p, err)
			}
			defer client.Close()

			port := freePort(t)
			if err := client.Listen(port, backend.Listener.Addr().String()); err != nil {
				t.Fatal(err)
			}
			waitForHTTP(t, port, "tunnelled", 5*time.Second)
		})
	}
}

// Many connections at once, on each protocol. One stream per tunnelled
// connection is the shape of all real traffic, and a multiplexer that crosses
// two of them is worse than one that is slow.
func TestConcurrentTunnelsOverEachProtocol(t *testing.T) {
	for _, p := range protocols {
		t.Run(string(p), func(t *testing.T) {
			ts := startProtocolServer(t, p)

			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(r.URL.Path))
			}))
			defer backend.Close()

			client := vtunnel.NewClient(wsURL(ts),
				vtunnel.WithProtocol(p),
				vtunnel.WithSecret(secretA),
			)
			if err := client.Connect(); err != nil {
				t.Fatal(err)
			}
			defer client.Close()

			port := freePort(t)
			if err := client.Listen(port, backend.Listener.Addr().String()); err != nil {
				t.Fatal(err)
			}
			waitForHTTP(t, port, "/", 5*time.Second)

			errs := make(chan error, 16)
			for i := range 16 {
				go func() {
					want := "/req/" + string(rune('a'+i))
					resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(port) + want)
					if err != nil {
						errs <- err
						return
					}
					defer resp.Body.Close()
					got, err := io.ReadAll(resp.Body)
					if err != nil {
						errs <- err
						return
					}
					if string(got) != want {
						errs <- fmt.Errorf("stream crossed: asked for %q, got %q", want, got)
						return
					}
					errs <- nil
				}()
			}
			for range 16 {
				if err := <-errs; err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// The transport is replaceable: plain TCP, no WebSocket anywhere, and the
// tunnel is exactly as authenticated because the session does that itself.
func TestTunnelOverTCPTransport(t *testing.T) {
	server := vtunnel.NewServer(vtunnel.WithServerSecret(secretA))

	ln, err := vtunnel.Listen("tcp://127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go vtunnel.Serve(ln, server)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("over tcp"))
	}))
	defer backend.Close()

	// No transport option anywhere: the scheme is the whole configuration.
	client := vtunnel.NewClient("tcp://"+ln.Addr().String(), vtunnel.WithSecret(secretA))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect over TCP: %v", err)
	}
	defer client.Close()

	port := freePort(t)
	if err := client.Listen(port, backend.Listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	waitForHTTP(t, port, "over tcp", 5*time.Second)
}

// The WebSocket transport reached the same way, with no HTTP server of the
// caller's own. This is the shorter path for a sandbox that has nothing else
// to serve.
func TestTunnelOverWebSocketListener(t *testing.T) {
	server := vtunnel.NewServer(vtunnel.WithServerSecret(secretA))

	ln, err := vtunnel.Listen("ws://127.0.0.1:0/")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go vtunnel.Serve(ln, server)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("over ws"))
	}))
	defer backend.Close()

	client := vtunnel.NewClient("ws://"+ln.Addr().String()+"/", vtunnel.WithSecret(secretA))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect over the WebSocket listener: %v", err)
	}
	defer client.Close()

	port := freePort(t)
	if err := client.Listen(port, backend.Listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	waitForHTTP(t, port, "over ws", 5*time.Second)
}

// An unusable URL surfaces from Connect, which is the first call that could
// have acted on it. NewClient does not return an error and should not grow one
// for this.
func TestUnknownTransportSchemeIsRefused(t *testing.T) {
	for _, url := range []string{"quic://sandbox:3001", "sandbox:3001"} {
		client := vtunnel.NewClient(url, vtunnel.WithSecret(secretA))
		err := client.Connect()
		client.Close()
		if err == nil {
			t.Fatalf("Connect accepted %q", url)
		}
		t.Logf("%s: %v", url, err)
	}
}

// A client holding the secret still gets nowhere against a sandbox speaking a
// different protocol. There is no negotiation on purpose, so this has to fail
// rather than quietly fall back to whichever end is older.
func TestProtocolMismatchIsRefused(t *testing.T) {
	ts := startProtocolServer(t, vtunnel.ProtocolYamux)

	client := vtunnel.NewClient(wsURL(ts),
		vtunnel.WithProtocol(vtunnel.ProtocolSSH),
		vtunnel.WithSecret(secretA),
	)

	done := make(chan error, 1)
	go func() { done <- client.Connect() }()

	select {
	case err := <-done:
		if err == nil {
			client.Close()
			t.Fatal("an SSH client connected to a yamux sandbox")
		}
		t.Logf("correctly refused: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("a protocol mismatch hung instead of failing")
	}
}
