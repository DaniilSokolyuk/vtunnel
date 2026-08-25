package vtunnel

// Fuzzing the front doors themselves, the way mitmproxy fuzzes its layers
// (test_http_fuzz.py, test_socks5_fuzz.py): feed the real thing arbitrary bytes
// in arbitrary pieces and require that it survives.
//
// The property-level targets next door check one function's rules. These check
// the whole door, and assert the two things a proxy owes whatever it is handed:
// the exchange ends, and the proxy is still serving afterwards. A panic in a
// connection goroutine takes the process down and the fuzzer reports it; a hang
// shows up as an exchange that never resolves; state corrupted by one client
// shows up in the known-good request that follows.

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// fuzzDoors builds the proxy and egress proxy once for the whole run: a listener per
// execution would spend the budget on setup and run out of ports.
var fuzzDoors = sync.OnceValues(func() (doors, error) {
	echo, err := listenEcho("echo")
	if err != nil {
		return doors{}, err
	}
	greeter, err := listenEcho("220 ready\r\n")
	if err != nil {
		return doors{}, err
	}

	blob, err := GenerateCA("fuzz")
	if err != nil {
		return doors{}, err
	}
	ca, err := LoadCA(blob)
	if err != nil {
		return doors{}, err
	}

	p := NewMITMProxy(WithMitmCA(ca))
	// Refuse what is not routed, the way a Client-managed controlplane does.
	// Without it an unrouted authority is dialled directly, and a fuzzer
	// inventing names finds real ones: the target would leave the machine, and
	// its timing would depend on somebody else's DNS.
	p.HandleUnmapped(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "vtunnel: domain not allowed", http.StatusForbidden)
	}))
	if err := p.ForwardTo("api.corp", echo); err != nil {
		return doors{}, err
	}
	if err := p.ForwardTo("greet.corp:25", greeter); err != nil {
		return doors{}, err
	}
	if err := p.ForwardTo("guarded.corp", echo, WithHeader("Authorization", "Bearer x")); err != nil {
		return doors{}, err
	}
	if err := p.Start("127.0.0.1:0"); err != nil {
		return doors{}, err
	}

	r := newEgressProxy()
	if err := r.Start("127.0.0.1:0"); err != nil {
		return doors{}, err
	}

	return doors{proxy: p.Addr().String(), egress: r.Addr().String(), echo: echo}, nil
})

type doors struct {
	proxy  string
	egress string
	echo   string
}

// listenEcho greets with banner, if any, and echoes the rest.
func listenEcho(banner string) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if banner != "" {
					io.WriteString(conn, banner)
				}
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String(), nil
}

// pour writes the script in pieces, so a message split where no client would
// split it is part of what is being tried.
func pour(conn net.Conn, script []byte, pieces int) {
	if pieces < 1 {
		pieces = 1
	}
	size := max(len(script)/pieces, 1)
	for len(script) > 0 {
		n := min(size, len(script))
		if _, err := conn.Write(script[:n]); err != nil {
			return
		}
		script = script[n:]
	}
}

// fuzzPatience is deliberately far larger than any bound the proxy is running
// under here (those are shortened to 200ms). It is not measuring latency: with
// a dozen fuzz workers competing for ports and CPU an exchange can take a while
// to get going, while a genuine hang has no bound at all and fails whatever the
// number is.
const fuzzPatience = 20 * time.Second

// resolves reports whether the exchange ended — answered, or hung up on.
func resolves(conn net.Conn, within time.Duration) bool {
	conn.SetReadDeadline(time.Now().Add(within))
	_, err := conn.Read(make([]byte, 1))
	if err == nil {
		return true
	}
	netErr, ok := err.(net.Error)
	return !ok || !netErr.Timeout()
}

// stillServing makes an ordinary request, so an execution that leaves the proxy
// broken is caught by the next one rather than by nothing.
func stillServing(t *testing.T, proxyAddr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		return // out of ports, not out of order
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(fuzzPatience))

	fmt.Fprint(conn, "CONNECT api.corp:443 HTTP/1.1\r\nHost: api.corp:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("the proxy stopped answering after this input: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the proxy answered a known-good CONNECT with %s after this input", resp.Status)
	}
}

func fuzzTimeouts(t *testing.T) {
	t.Helper()
	// Every bound a half-finished message can run into, shortened together, so
	// the target measures "inside its configured bound" rather than waiting one
	// out. A client that sends the first bytes of a TLS record and stops is
	// held by the handshake timeout, not by the peek.
	header, peek, handshake := serverReadHeaderTimeout.Get(), peekTimeout.Get(), mitmHandshakeTimeout.Get()
	silence := 200 * time.Millisecond
	t.Cleanup(func() {
		serverReadHeaderTimeout.Set(header)
		peekTimeout.Set(peek)
		mitmHandshakeTimeout.Set(handshake)
	})
	serverReadHeaderTimeout.Set(silence)
	peekTimeout.Set(silence)
	mitmHandshakeTimeout.Set(silence)
}

// The proxy's own port: anything a client can write before the proxy knows what
// it is talking to.
func FuzzProxyPortSurvivesAnything(f *testing.F) {
	f.Add([]byte("GET http://api.corp/ HTTP/1.1\r\nHost: api.corp\r\n\r\n"), 1)
	f.Add([]byte("CONNECT api.corp:443 HTTP/1.1\r\nHost: api.corp:443\r\n\r\n"), 3)
	f.Add([]byte("CONNECT \x00\xff:443 HTTP/1.1\r\nHost: x\r\n\r\n"), 1)
	f.Add([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00"), 2)
	f.Add([]byte{0x05, 0x01, 0x00}, 1)
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x01, 0x00}, 1)
	f.Add([]byte("GET / HTTP/1.1\r\nHost: api.corp\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"), 4)

	fuzzOverASocket(f, func(d doors) string { return d.proxy })
}

// The sandbox egress proxy's mixed port, which sorts HTTP from SOCKS5 by one byte and
// therefore has two parsers behind it.
func FuzzEgressPortSurvivesAnything(f *testing.F) {
	f.Add([]byte{5, 1, 0, 5, 1, 0, 3, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0, 80}, 1)
	f.Add([]byte{5, 1, 0, 5, 1, 0, 3, 255}, 1)
	f.Add([]byte{5, 255}, 1)
	f.Add([]byte("CONNECT localhost:9 HTTP/1.1\r\nHost: localhost:9\r\n\r\n"), 2)
	f.Add([]byte("GET http://localhost:9/ HTTP/1.1\r\n\r\n"), 3)
	f.Add([]byte{5, 1, 0, 5, 1, 0, 4, 0, 0}, 1)

	fuzzOverASocket(f, func(d doors) string { return d.egress })
}

func fuzzOverASocket(f *testing.F, pick func(doors) string) {
	f.Fuzz(func(t *testing.T, script []byte, pieces int) {
		fuzzTimeouts(t)
		d, err := fuzzDoors()
		if err != nil {
			t.Skipf("could not stand up the doors: %v", err)
		}

		conn, err := net.DialTimeout("tcp", pick(d), fuzzPatience)
		if err != nil {
			t.Skipf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * fuzzPatience))

		pour(conn, script, pieces)
		if !resolves(conn, fuzzPatience) {
			t.Fatalf("neither answered nor closed")
		}
		conn.Close()

		stillServing(t, d.proxy)
	})
}

// Inside an established tunnel, where the bytes decide whether the connection
// is intercepted or piped — and where the sandbox chooses them.
func FuzzTunnelInteriorSurvivesAnything(f *testing.F) {
	f.Add("api.corp:443", []byte{0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5}, 1)
	f.Add("api.corp:80", []byte("GET / HTTP/1.1\r\nHost: api.corp\r\n\r\n"), 3)
	f.Add("guarded.corp:443", []byte("GET / HTTP/1.1\nHost: guarded.corp\n\n"), 2)
	f.Add("greet.corp:25", []byte(nil), 1)
	f.Add("api.corp:443", []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), 5)
	f.Add("api.corp:443", []byte{0x00, 0x01, 0x02, 0x03}, 1)
	// A TLS record header and then silence: classified as TLS, so the handshake
	// is what ends it rather than the peek. Found by the fuzzer, kept here
	// because a corpus file under testdata is one `rm` from gone.
	f.Add("api.corp:443", []byte{0x16, 0x03, 0x02, 0x01, 0x04, 0x05}, 1)

	f.Fuzz(func(t *testing.T, authority string, script []byte, pieces int) {
		if !isRoutableAuthority(authority) {
			t.Skip("not an authority a CONNECT could carry")
		}
		fuzzTimeouts(t)
		d, err := fuzzDoors()
		if err != nil {
			t.Skipf("could not stand up the doors: %v", err)
		}

		conn, err := net.DialTimeout("tcp", d.proxy, fuzzPatience)
		if err != nil {
			t.Skipf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * fuzzPatience))

		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Skip("the CONNECT itself did not go through")
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return // refused, which is an ending
		}

		pour(conn, script, pieces)
		if !resolves(conn, fuzzPatience) {
			// A silent client on a route that may be piped is a legitimate open
			// tunnel — that is how SMTP works — so only a client that said
			// something is owed an ending.
			if len(script) > 0 {
				t.Fatalf("the tunnel neither carried anything nor ended")
			}
		}
		conn.Close()

		stillServing(t, d.proxy)
	})
}
