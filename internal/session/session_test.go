package session

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel/internal/tunnelkey"
)

var kinds = []Kind{KindSSH, KindYamux}

const (
	secretA = "8Kq2vX7mR4nP1tY5uB9cD3fJ6wZ0aE"
	secretB = "3f2a9c41-77b1-4de6-9f0a-1c5e8b2d4a63"
)

func keysFor(t *testing.T, secret string) *tunnelkey.Keys {
	t.Helper()
	k, err := tunnelkey.Derive(secret)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// pair runs both halves of a handshake over a loopback TCP connection and
// hands back the two sessions. serverErr is nil only if the server half also
// succeeded, which is what a test for a rejected client needs to check.
func pair(t *testing.T, kind Kind, clientKeys, serverKeys *tunnelkey.Keys) (client Session, serverErr <-chan error) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		s, err := Serve(kind, conn, Config{Keys: serverKeys, Handshake: 10 * time.Second})
		if err != nil {
			srvErr <- err
			return
		}
		srvErr <- nil
		go echo(s)
		t.Cleanup(func() { s.Close() })
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := Dial(kind, conn, Config{Keys: clientKeys, Handshake: 10 * time.Second})
	if err != nil {
		return nil, srvErr
	}
	t.Cleanup(func() { c.Close() })
	return c, srvErr
}

// echo accepts every stream and copies it back, so a test can prove that bytes
// actually traverse the session rather than that a handshake merely returned.
func echo(s Session) {
	for {
		stream, err := s.Accept()
		if err != nil {
			return
		}
		go func() {
			defer stream.Close()
			io.Copy(stream, stream)
		}()
	}
}

// The point of the abstraction: every backend carries bytes on a stream, and
// the tunnel above it cannot tell which one it is talking to.
func TestRoundTrip(t *testing.T) {
	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			keys := keysFor(t, secretA)
			c, srvErr := pair(t, kind, keys, keys)
			if c == nil {
				t.Fatalf("client handshake failed; server said: %v", <-srvErr)
			}
			if err := <-srvErr; err != nil {
				t.Fatalf("server handshake: %v", err)
			}

			stream, err := c.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()

			const msg = "the tunnel does not care which multiplexer this is"
			if _, err := stream.Write([]byte(msg)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(stream, buf); err != nil {
				t.Fatal(err)
			}
			if string(buf) != msg {
				t.Fatalf("got %q, want %q", buf, msg)
			}
		})
	}
}

// Many streams at once is the normal case — one per tunnelled connection.
func TestConcurrentStreams(t *testing.T) {
	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			keys := keysFor(t, secretA)
			c, srvErr := pair(t, kind, keys, keys)
			if c == nil {
				t.Fatalf("client handshake failed; server said: %v", <-srvErr)
			}
			<-srvErr

			done := make(chan error, 8)
			for i := range 8 {
				go func() {
					stream, err := c.Open()
					if err != nil {
						done <- err
						return
					}
					defer stream.Close()
					msg := []byte{byte('a' + i)}
					if _, err := stream.Write(msg); err != nil {
						done <- err
						return
					}
					buf := make([]byte, 1)
					if _, err := io.ReadFull(stream, buf); err != nil {
						done <- err
						return
					}
					if buf[0] != msg[0] {
						done <- errors.New("stream crossed with another")
						return
					}
					done <- nil
				}()
			}
			for range 8 {
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// A peer holding a different secret gets nowhere, on either backend — and the
// failure surfaces from Dial, not on some later read. TLS 1.3 makes that worth
// asserting: the client finishes its handshake before the server has looked at
// its certificate, so without the hello exchange this would pass and fail later.
func TestWrongSecretIsRefused(t *testing.T) {
	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			c, srvErr := pair(t, kind, keysFor(t, secretB), keysFor(t, secretA))
			if c != nil {
				t.Fatal("Dial succeeded with a secret the server does not share")
			}
			if err := <-srvErr; err == nil {
				t.Fatal("the server accepted a client holding a different secret")
			} else {
				t.Logf("correctly rejected: %v", err)
			}
		})
	}
}

// No keys at all: encrypted, unauthenticated, still working. Every backend
// offers the same bargain, and the caller has been warned elsewhere.
func TestUnauthenticated(t *testing.T) {
	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			c, srvErr := pair(t, kind, nil, nil)
			if c == nil {
				t.Fatalf("client handshake failed; server said: %v", <-srvErr)
			}
			if err := <-srvErr; err != nil {
				t.Fatalf("server handshake: %v", err)
			}
			stream, err := c.Open()
			if err != nil {
				t.Fatal(err)
			}
			stream.Close()
		})
	}
}

// Wait unblocks when the peer goes away, which is what drives reconnection.
func TestWaitReturnsOnClose(t *testing.T) {
	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			keys := keysFor(t, secretA)
			c, srvErr := pair(t, kind, keys, keys)
			if c == nil {
				t.Fatalf("client handshake failed; server said: %v", <-srvErr)
			}
			<-srvErr

			done := make(chan struct{})
			go func() { c.Wait(); close(done) }()
			c.Close()

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Wait did not return after Close")
			}
		})
	}
}
