package socks5

// The SOCKS5 handshake against arbitrary bytes.
//
// mitmproxy fuzzes the same surface (test/mitmproxy/proxy/layers/test_socks5_fuzz.py)
// for the same reason: everything after the version byte is attacker-chosen and
// length-prefixed, and what comes out the other end is a hostname this proxy
// then writes into a text protocol.

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// scriptedConn replays a fixed script to the reader and throws away everything
// written back, so a refusal that nobody is listening for cannot deadlock.
type scriptedConn struct {
	r io.Reader
}

func (c *scriptedConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c *scriptedConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *scriptedConn) Close() error                     { return nil }
func (c *scriptedConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *scriptedConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "test" }
func (dummyAddr) String() string  { return "test" }

func FuzzAccept(f *testing.F) {
	f.Add([]byte{5, 1, 0, 5, 1, 0, 3, 7, 'd', 'b', '.', 'c', 'o', 'r', 'p', 0x15, 0x38})
	f.Add([]byte{5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 1, 187})
	f.Add([]byte{5, 1, 0, 5, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187})
	f.Add([]byte{5, 2})                     // a greeting that stops halfway
	f.Add([]byte{5, 1, 0, 5, 2, 0, 3, 0})   // BIND, empty domain
	f.Add([]byte{5, 1, 0, 5, 1, 0, 3, 255}) // a length that overstates
	f.Add([]byte{4, 1, 0})                  // SOCKS4

	f.Fuzz(func(t *testing.T, script []byte) {
		// No timeout: the script ends in EOF, so a correct parser returns
		// without one. Needing a deadline to finish would be the bug.
		req, err := Accept(&scriptedConn{r: strings.NewReader(string(script))}, 0)
		if err != nil {
			if req != nil {
				t.Fatalf("both a request and an error: %v", err)
			}
			return
		}

		// Whatever came back is about to be treated as a destination: matched
		// against the allowlist, and written into the request line and Host
		// header of a CONNECT on the tunnel. It has to be a host and a port.
		host, port, splitErr := net.SplitHostPort(req.Target)
		if splitErr != nil {
			t.Fatalf("accepted target %q is not host:port: %v", req.Target, splitErr)
		}
		if host == "" {
			t.Fatalf("accepted an empty host (target %q); in Go that dials the local machine", req.Target)
		}
		if net.ParseIP(host) == nil && !isHostname(host) {
			t.Fatalf("accepted %q, which is neither an address nor a hostname", host)
		}
		for _, c := range []string{"\r", "\n", "\x00", " ", "\t"} {
			if strings.Contains(req.Target, c) {
				t.Fatalf("accepted target %q contains %q, which would break the "+
					"request line it is written into", req.Target, c)
			}
		}
		if _, err := net.LookupPort("tcp", port); err != nil {
			t.Fatalf("accepted port %q: %v", port, err)
		}
	})
}

// isHostname is the check under test; this pins the property the rest of the
// system relies on rather than the spelling of the rule.
func FuzzIsHostname(f *testing.F) {
	f.Add("db.corp")
	f.Add("a\r\n\r\nCONNECT 10.0.0.1:22 HTTP/1.1\r\n\r\n.corp")
	f.Add("")
	f.Add("..")
	f.Add(strings.Repeat("a", 300))
	f.Add("тест.example")

	f.Fuzz(func(t *testing.T, host string) {
		if !isHostname(host) {
			return
		}
		if host == "" {
			t.Fatal("the empty string is not a hostname")
		}
		for i := range len(host) {
			c := host[i]
			if c < 0x21 || c > 0x7e {
				t.Fatalf("accepted %q, which contains byte %#x — anything outside "+
					"printable ASCII cannot survive a text protocol", host, c)
			}
			switch c {
			case ':', '/', '\\', '@', '?', '#', '[', ']', '%', '*':
				t.Fatalf("accepted %q, which contains %q and would change the meaning "+
					"of an authority it is placed in", host, string(c))
			}
		}
		// Round-trips through the pair of functions every caller uses.
		hostPort := net.JoinHostPort(host, "443")
		back, port, err := net.SplitHostPort(hostPort)
		if err != nil || back != host || port != "443" {
			t.Fatalf("%q does not survive JoinHostPort/SplitHostPort: %q %q %v", host, back, port, err)
		}
	})
}
