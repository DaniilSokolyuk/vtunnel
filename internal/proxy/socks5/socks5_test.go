package socks5

// The SOCKS5 handshake, and nothing else.
//
// This package's whole job is to learn one "host:port" from a client and to
// answer it once the caller knows whether that connection happened. It makes no
// decision about where the traffic goes — that belongs to whoever holds the
// allowlist — which is the same split mitmproxy draws: its Socks5Proxy layer
// sets context.server.address and hands over to the next layer.

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// client is the far end of a net.Pipe, driven by hand so every byte of the
// protocol is visible in the test.
type client struct {
	t    *testing.T
	conn net.Conn
}

// newPair connects a client to a server over real TCP rather than net.Pipe.
// The refusal paths stop reading mid-request, which an unbuffered pipe turns
// into a deadlock that has nothing to do with the protocol.
func newPair(t *testing.T) (*client, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- conn
	}()

	clientSide, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	server := <-accepted

	t.Cleanup(func() {
		server.Close()
		clientSide.Close()
	})
	return &client{t: t, conn: clientSide}, server
}

// write is safe to call from another goroutine, so it reports with Errorf
// rather than Fatalf.
func (c *client) write(b ...byte) {
	c.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.conn.Write(b); err != nil {
		c.t.Errorf("write %v: %v", b, err)
	}
}

func (c *client) read(n int) []byte {
	c.t.Helper()
	buf := make([]byte, n)
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c.conn, buf); err != nil {
		c.t.Fatalf("read %d bytes: %v", n, err)
	}
	return buf
}

// greet sends the version identifier offering no-authentication and checks the
// method selection.
func (c *client) greet() {
	c.t.Helper()
	c.write(Version, 1, MethodNoAuth)
	if got := c.read(2); got[0] != Version || got[1] != MethodNoAuth {
		c.t.Fatalf("method selection = % x, want 05 00", got)
	}
}

func TestAcceptDomainRequest(t *testing.T) {
	cli, server := newPair(t)

	accepted := make(chan *Request, 1)
	failed := make(chan error, 1)
	go func() {
		req, err := Accept(server, time.Second)
		if err != nil {
			failed <- err
			return
		}
		accepted <- req
	}()

	cli.greet()
	// CONNECT db.corp:5432, as a domain name — the form that keeps the name
	// alive all the way to the allowlist.
	cli.write(Version, CmdConnect, 0x00, AddrDomain, byte(len("db.corp")))
	cli.write([]byte("db.corp")...)
	cli.write(0x15, 0x38) // 5432

	select {
	case err := <-failed:
		t.Fatalf("Accept: %v", err)
	case req := <-accepted:
		if req.Target != "db.corp:5432" {
			t.Fatalf("Target = %q, want db.corp:5432", req.Target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept never returned")
	}
}

func TestAcceptIPRequests(t *testing.T) {
	cases := []struct {
		name string
		atyp byte
		addr []byte
		want string
	}{
		{name: "IPv4", atyp: AddrIPv4, addr: []byte{10, 0, 0, 7}, want: "10.0.0.7:443"},
		{
			name: "IPv6",
			atyp: AddrIPv6,
			addr: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			want: "[2001:db8::1]:443",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cli, server := newPair(t)

			got := make(chan string, 1)
			bad := make(chan error, 1)
			go func() {
				req, err := Accept(server, time.Second)
				if err != nil {
					bad <- err
					return
				}
				got <- req.Target
			}()

			cli.greet()
			cli.write(Version, CmdConnect, 0x00, tc.atyp)
			cli.write(tc.addr...)
			cli.write(0x01, 0xbb) // 443

			select {
			case err := <-bad:
				t.Fatalf("Accept: %v", err)
			case target := <-got:
				if target != tc.want {
					t.Fatalf("Target = %q, want %q", target, tc.want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Accept never returned")
			}
		})
	}
}

// BIND and UDP ASSOCIATE are refused with the code the RFC has for exactly
// this, so a client fails immediately and legibly instead of waiting for a
// tunnel that is never coming. It is what mitmproxy answers too.
func TestUnsupportedCommandsAreRefused(t *testing.T) {
	for _, cmd := range []byte{CmdBind, CmdUDPAssociate} {
		cli, server := newPair(t)

		done := make(chan error, 1)
		go func() {
			_, err := Accept(server, time.Second)
			done <- err
		}()

		cli.greet()
		cli.write(Version, cmd, 0x00, AddrIPv4, 10, 0, 0, 7, 0x01, 0xbb)

		reply := cli.read(10)
		if reply[0] != Version || reply[1] != RepCommandNotSupported {
			t.Fatalf("cmd %#x: reply = % x, want 05 07 …", cmd, reply)
		}
		if err := <-done; err == nil {
			t.Fatalf("cmd %#x: Accept returned no error", cmd)
		}
	}
}

func TestUnknownAddressTypeIsRefused(t *testing.T) {
	cli, server := newPair(t)

	done := make(chan error, 1)
	go func() {
		_, err := Accept(server, time.Second)
		done <- err
	}()

	cli.greet()
	cli.write(Version, CmdConnect, 0x00, 0x09, 0, 0)

	reply := cli.read(10)
	if reply[1] != RepAddrTypeNotSupported {
		t.Fatalf("reply = % x, want 05 08 …", reply)
	}
	if err := <-done; err == nil {
		t.Fatal("Accept returned no error")
	}
}

// A client that offers only authentication methods this server does not
// implement is told so, rather than being left to guess.
func TestNoAcceptableAuthMethod(t *testing.T) {
	cli, server := newPair(t)

	done := make(chan error, 1)
	go func() {
		_, err := Accept(server, time.Second)
		done <- err
	}()

	cli.write(Version, 1, MethodUserPassword)

	reply := cli.read(2)
	if reply[0] != Version || reply[1] != MethodNoAcceptable {
		t.Fatalf("reply = % x, want 05 ff", reply)
	}
	if err := <-done; err == nil {
		t.Fatal("Accept returned no error")
	}
}

func TestWrongVersionIsRefused(t *testing.T) {
	cli, server := newPair(t)

	done := make(chan error, 1)
	go func() {
		_, err := Accept(server, time.Second)
		done <- err
	}()

	// SOCKS4, or an HTTP request that wandered in.
	cli.write(0x04, 0x01)

	if err := <-done; err == nil {
		t.Fatal("Accept accepted something that is not SOCKS5")
	}
}

// Half a handshake must not cost a goroutine and a descriptor for the life of
// the process.
func TestHandshakeHasADeadline(t *testing.T) {
	cli, server := newPair(t)

	done := make(chan error, 1)
	go func() {
		_, err := Accept(server, 100*time.Millisecond)
		done <- err
	}()

	cli.write(Version, 1) // promises a method byte, never sends it

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Accept returned successfully on a truncated handshake")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept is still waiting for a client that stopped talking")
	}
}

// Grant and Refuse are the two answers the caller owes the client once it knows
// whether the connection happened.
func TestGrantAndRefuse(t *testing.T) {
	t.Run("grant", func(t *testing.T) {
		cli, server := newPair(t)
		reqCh := make(chan *Request, 1)
		go func() {
			req, err := Accept(server, time.Second)
			if err != nil {
				t.Error(err)
				return
			}
			reqCh <- req
		}()

		cli.greet()
		cli.write(Version, CmdConnect, 0x00, AddrIPv4, 127, 0, 0, 1, 0x01, 0xbb)

		req := <-reqCh
		if err := req.Grant(); err != nil {
			t.Fatalf("Grant: %v", err)
		}

		reply := cli.read(10)
		if reply[0] != Version || reply[1] != RepSuccess {
			t.Fatalf("reply = % x, want 05 00 …", reply)
		}
	})

	t.Run("refuse", func(t *testing.T) {
		cli, server := newPair(t)
		reqCh := make(chan *Request, 1)
		go func() {
			req, err := Accept(server, time.Second)
			if err != nil {
				t.Error(err)
				return
			}
			reqCh <- req
		}()

		cli.greet()
		cli.write(Version, CmdConnect, 0x00, AddrIPv4, 127, 0, 0, 1, 0x01, 0xbb)

		req := <-reqCh
		if err := req.Refuse(RepNotAllowed); err != nil {
			t.Fatalf("Refuse: %v", err)
		}

		reply := cli.read(10)
		if reply[1] != RepNotAllowed {
			t.Fatalf("reply = % x, want 05 02 …", reply)
		}
	})
}

// A dial error is turned into the closest reply code, so the client's error
// message says something true about what happened.
func TestReplyCodeForError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want byte
	}{
		{name: "refused", err: &net.OpError{Err: errConnRefused{}}, want: RepConnRefused},
		{name: "anything else", err: errors.New("boom"), want: RepHostUnreachable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ReplyCode(tc.err); got != tc.want {
				t.Fatalf("ReplyCode(%v) = %#x, want %#x", tc.err, got, tc.want)
			}
		})
	}
}

type errConnRefused struct{}

func (errConnRefused) Error() string { return "connection refused" }

// The domain field is 255 arbitrary bytes, and nothing between the socket and
// the allowlist looked at them. Whatever the client wrote travelled on as a
// hostname: into the request line and Host header of the CONNECT the egress
// proxy synthesises for the controlplane, and into the logs. A name is a name — the
// characters a hostname may contain are not a matter of taste here, they are
// what keeps a client from writing a second request inside the first.
func TestAcceptRefusesDomainsThatAreNotHostnames(t *testing.T) {
	bad := map[string]string{
		"embedded CRLF":     "a\r\n\r\nCONNECT 10.0.0.1:22 HTTP/1.1\r\nHost: 10.0.0.1:22\r\n\r\n.corp",
		"bare CR":           "a\r.corp",
		"bare LF":           "a\n.corp",
		"space":             "a b.corp",
		"tab":               "a\t.corp",
		"NUL":               "a\x00.corp",
		"colon":             "a:22.corp",
		"empty":             "",
		"only dots":         "..",
		"empty label":       "a..corp",
		"label starts bad":  "-a.corp",
		"non-ASCII":         "тест.example",
		"leading dot":       ".corp",
		"control character": "a\x7f.corp",
	}

	for name, domain := range bad {
		t.Run(name, func(t *testing.T) {
			cli, server := newPair(t)

			failed := make(chan error, 1)
			accepted := make(chan *Request, 1)
			go func() {
				req, err := Accept(server, time.Second)
				if err != nil {
					failed <- err
					return
				}
				accepted <- req
			}()

			cli.greet()
			cli.write(Version, CmdConnect, 0x00, AddrDomain, byte(len(domain)))
			if len(domain) > 0 {
				cli.write([]byte(domain)...)
			}
			cli.write(0x01, 0xbb) // 443

			select {
			case req := <-accepted:
				t.Fatalf("accepted %q as a hostname (target %q)", domain, req.Target)
			case err := <-failed:
				if err == nil {
					t.Fatal("no error")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Accept neither returned nor refused")
			}

			if got := cli.read(2); got[0] != Version || got[1] == RepSuccess {
				t.Fatalf("reply = % x, want a refusal", got)
			}
		})
	}
}

// What a hostname may look like, so the check above is not quietly stricter
// than the names people actually use.
func TestAcceptAllowsOrdinaryHostnames(t *testing.T) {
	for _, domain := range []string{
		"db.corp",
		"a.b.c.d.example.com",
		"api-gateway.internal",
		"host_with_underscore.corp", // common in service discovery
		"xn--e1aybc.example",        // punycode
		"localhost",
		"api.corp.",  // fully qualified
		"9front.org", // a label may start with a digit
	} {
		t.Run(domain, func(t *testing.T) {
			cli, server := newPair(t)

			accepted := make(chan *Request, 1)
			failed := make(chan error, 1)
			go func() {
				req, err := Accept(server, time.Second)
				if err != nil {
					failed <- err
					return
				}
				accepted <- req
			}()

			cli.greet()
			cli.write(Version, CmdConnect, 0x00, AddrDomain, byte(len(domain)))
			cli.write([]byte(domain)...)
			cli.write(0x01, 0xbb)

			select {
			case req := <-accepted:
				if req.Target != net.JoinHostPort(domain, "443") {
					t.Fatalf("target = %q", req.Target)
				}
			case err := <-failed:
				t.Fatalf("refused an ordinary hostname: %v", err)
			case <-time.After(3 * time.Second):
				t.Fatal("Accept neither returned nor refused")
			}
		})
	}
}
