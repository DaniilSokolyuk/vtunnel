package vtunnel

// Both front doors, given things no well-behaved client sends. The bar is not
// that any of it works — most of it is nonsense — but that every one of them
// ends inside the proxy's own bounds: an answer, or a closed connection, and
// never a connection left parked holding a goroutine and a descriptor.

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// speak sends one thing a client might send and reports what came of it. A
// single byte back is enough to count as an answer; so is being hung up on.
// Neither, within the limit, is the failure this is looking for.
func speak(t *testing.T, addr string, payload []byte, limit time.Duration) (answered bool, took time.Duration) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	start := time.Now()
	conn.SetDeadline(time.Now().Add(limit))
	if _, err := conn.Write(payload); err != nil {
		return true, time.Since(start) // refused at the socket, which is an ending
	}

	if _, err := conn.Read(make([]byte, 1)); err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return false, time.Since(start)
		}
		return true, time.Since(start) // EOF or reset: hung up on
	}
	return true, time.Since(start)
}

// greetingBackend speaks first and then echoes, the way SMTP, IMAP and the
// database protocols do.
func greetingBackend(t *testing.T, banner string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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
				io.WriteString(conn, banner)
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func robustnessDoors(t *testing.T) (proxyAddr, routerAddr string) {
	t.Helper()

	echo := echoBackend(t)

	blob, err := GenerateCA("robustness")
	if err != nil {
		t.Fatal(err)
	}
	ca, err := LoadCA(blob)
	if err != nil {
		t.Fatal(err)
	}

	p := NewMITMProxy(WithMitmCA(ca))
	if err := p.ForwardTo("api.corp", echo); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.ForwardTo("guarded.corp", echo, WithHeader("Authorization", "Bearer x")); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(p.Close)

	r := newRouter()
	if err := r.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("router Start: %v", err)
	}
	t.Cleanup(r.Close)

	return p.Addr().String(), r.Addr().String()
}

func TestBothFrontDoorsSurviveOddInput(t *testing.T) {
	// Shortened so the test measures "inside the configured bound" rather than
	// waiting one out. Between them these two are what bound a client that
	// starts something and does not finish it: the header timeout on the HTTP
	// side, the peek timeout on the SOCKS5 handshake and the tunnel's first
	// byte.
	// Restored with Cleanup, not defer: the subtests below run in parallel,
	// which means after this function body returns.
	header, peek := serverReadHeaderTimeout, peekTimeout
	t.Cleanup(func() { serverReadHeaderTimeout, peekTimeout = header, peek })
	serverReadHeaderTimeout = 2 * time.Second
	peekTimeout = 2 * time.Second
	const limit = 20 * time.Second

	proxyAddr, routerAddr := robustnessDoors(t)

	long := strings.Repeat("a", 300)
	cases := []struct {
		name    string
		payload []byte
	}{
		{"nothing but blank lines", []byte("\r\n\r\n")},
		{"a single byte", []byte("X")},
		{"NUL bytes", []byte{0, 0, 0, 0, 0, 0, 0, 0}},
		{"a TLS record on a plain proxy port", []byte{0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5}},
		{"the h2c preface and nothing else", []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")},
		{"a request line with no version", []byte("GET /\r\n\r\n")},
		{"a method nobody registered", []byte("BREW /coffee HTTP/1.1\r\nHost: api.corp\r\n\r\n")},
		{"an absurdly long authority", []byte("CONNECT " + long + "." + long + ":443 HTTP/1.1\r\nHost: x\r\n\r\n")},
		{"a wildcard authority", []byte("CONNECT *.corp:443 HTTP/1.1\r\nHost: *.corp:443\r\n\r\n")},
		{"an authority with no port", []byte("CONNECT api.corp HTTP/1.1\r\nHost: api.corp\r\n\r\n")},
		{"an authority that is only a port", []byte("CONNECT :443 HTTP/1.1\r\nHost: :443\r\n\r\n")},
		{"an authority with a CR in it", []byte("CONNECT a\rb.corp:443 HTTP/1.1\r\nHost: x\r\n\r\n")},
		{"a negative content length", []byte("POST / HTTP/1.1\r\nHost: api.corp\r\nContent-Length: -1\r\n\r\n")},
		{"two content lengths", []byte("POST / HTTP/1.1\r\nHost: api.corp\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx")},
		{"a header with no colon", []byte("GET / HTTP/1.1\r\nHost: api.corp\r\nbroken\r\n\r\n")},
		{"a SOCKS5 greeting cut in half", []byte{5, 2}},
		{"SOCKS5 with an unknown command", []byte{5, 1, 0, 5, 2, 0, 3, 7, 'a', '.', 'c', 'o', 'r', 'p', 1, 187}},
		{"SOCKS5 whose domain length overstates", []byte{5, 1, 0, 5, 1, 0, 3, 40, 'a', '.', 'c', 'o', 'r', 'p'}},
		{"SOCKS5 for an empty domain", []byte{5, 1, 0, 5, 1, 0, 3, 0, 1, 187}},
		{"SOCKS5 for an address literal", []byte{5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 1, 187}},
		{"a request line longer than the peek buffer", []byte("GET /" + strings.Repeat("q", 20000) + " HTTP/1.1\r\nHost: api.corp\r\n\r\n")},
	}

	for _, door := range []struct{ name, addr string }{
		{"proxy", proxyAddr},
		{"router", routerAddr},
	} {
		for _, tc := range cases {
			t.Run(door.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				if answered, took := speak(t, door.addr, tc.payload, limit); !answered {
					t.Fatalf("neither answered nor closed in %v", took)
				}
			})
		}
	}
}

// The tunnel half of the same question: once a CONNECT is through, the bytes
// inside it are equally arbitrary, and the classification that reads them must
// end whatever they are.
func TestTunnelledOddInputAlwaysResolves(t *testing.T) {
	// The upstream greets, so "the tunnel resolved" is observable whichever way
	// it resolved: terminated and answered, or piped and the banner came back.
	// A silent client on a pipeable route is a legitimate open tunnel — that is
	// the SMTP case — and with a silent upstream too there would be nothing to
	// see.
	banner := greetingBackend(t, "220 ready\r\n")

	blob, err := GenerateCA("tunnelled-odd")
	if err != nil {
		t.Fatal(err)
	}
	ca, err := LoadCA(blob)
	if err != nil {
		t.Fatal(err)
	}
	p := NewMITMProxy(WithMitmCA(ca))
	if err := p.ForwardTo("api.corp", banner); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(p.Close)
	proxyAddr := p.Addr().String()

	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"nothing at all", nil},
		{"one byte", []byte{'?'}},
		{"a truncated TLS record header", []byte{0x16, 0x03}},
		{"a TLS record header for a version that does not exist", []byte{0x16, 0x09, 0x09, 0, 0}},
		{"half the h2c preface", []byte("PRI * HTTP/2.0\r\n")},
		{"a request line that never ends", []byte("GET /" + strings.Repeat("q", 200))},
		{"printable bytes that are not a request", []byte("HELLO THERE FRIEND")},
		{"binary", []byte{0x00, 0x01, 0x02, 0xff, 0xfe}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(30 * time.Second))

			if _, err := io.WriteString(conn, "CONNECT api.corp:443 HTTP/1.1\r\nHost: api.corp:443\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			head := make([]byte, len("HTTP/1.1 200 Connection Established\r\n\r\n"))
			if _, err := io.ReadFull(conn, head); err != nil {
				t.Fatalf("CONNECT: %v", err)
			}

			start := time.Now()
			if len(tc.payload) > 0 {
				conn.Write(tc.payload)
			}
			// api.corp is a header-free route, so an unrecognised stream is
			// piped to the upstream, whose banner comes back.
			if _, err := conn.Read(make([]byte, 1)); err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					t.Fatalf("the tunnel neither carried anything nor ended in %v", time.Since(start))
				}
			}
		})
	}
}
