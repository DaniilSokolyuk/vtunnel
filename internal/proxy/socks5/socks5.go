// Package socks5 is the server half of a SOCKS5 handshake, and deliberately
// nothing more.
//
// It learns one "host:port" from a client and answers it once the caller knows
// whether that connection could be made. Where the traffic then goes — through
// a tunnel, straight out, or nowhere at all — is the caller's decision, because
// the caller is the one holding the allowlist. That is the same split
// mitmproxy draws: its Socks5Proxy layer sets context.server.address and hands
// the connection to the next layer without an opinion.
//
// Only CONNECT is implemented. BIND and UDP ASSOCIATE are answered with
// "command not supported", which is what mitmproxy answers too: a UDP
// association would need a second socket and a datagram path through whatever
// is carrying the traffic, and refusing it up front lets a client fail
// immediately rather than wait for something that is not coming.
package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Version is the only protocol version this package speaks.
const Version = 0x05

// Authentication methods (RFC 1928 §3).
const (
	MethodNoAuth       = 0x00
	MethodUserPassword = 0x02
	MethodNoAcceptable = 0xFF
)

// Commands (RFC 1928 §4).
const (
	CmdConnect      = 0x01
	CmdBind         = 0x02
	CmdUDPAssociate = 0x03
)

// Address types (RFC 1928 §4).
const (
	AddrIPv4   = 0x01
	AddrDomain = 0x03
	AddrIPv6   = 0x04
)

// Reply codes (RFC 1928 §6).
const (
	RepSuccess              = 0x00
	RepGeneralFailure       = 0x01
	RepNotAllowed           = 0x02
	RepHostUnreachable      = 0x04
	RepConnRefused          = 0x05
	RepCommandNotSupported  = 0x07
	RepAddrTypeNotSupported = 0x08
)

// Request is one CONNECT the client is waiting on an answer to.
//
// Exactly one of [Request.Grant] or [Request.Refuse] must be called, and the
// bytes that follow belong to the tunnelled connection.
type Request struct {
	// Target is what the client asked for, as it asked for it: a domain name
	// stays a domain name. That matters — the allowlist matches on names, and
	// resolving here would turn every request into an address nothing can
	// recognise.
	Target string

	conn net.Conn
}

// Accept performs the greeting and reads one CONNECT request.
//
// timeout bounds the whole handshake and is cleared before returning, so it
// never cuts into the traffic that follows. On any error the client has already
// been told what went wrong where the protocol has a way to say it; the caller
// only has to close the connection.
func Accept(conn net.Conn, timeout time.Duration) (*Request, error) {
	if timeout > 0 {
		conn.SetDeadline(time.Now().Add(timeout))
		defer conn.SetDeadline(time.Time{})
	}

	if err := greet(conn); err != nil {
		return nil, err
	}

	// VER CMD RSV ATYP, then an address whose length depends on ATYP.
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, fmt.Errorf("socks5: read request: %w", err)
	}
	if head[0] != Version {
		return nil, fmt.Errorf("socks5: request version %#x, want %#x", head[0], Version)
	}
	if head[1] != CmdConnect {
		reply(conn, RepCommandNotSupported)
		return nil, fmt.Errorf("socks5: command %#x is not supported (only CONNECT)", head[1])
	}

	host, err := readAddress(conn, head[3])
	if err != nil {
		switch {
		case errors.Is(err, errAddrType):
			reply(conn, RepAddrTypeNotSupported)
		case errors.Is(err, errBadDomain):
			reply(conn, RepNotAllowed)
		}
		return nil, err
	}

	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return nil, fmt.Errorf("socks5: read port: %w", err)
	}

	return &Request{
		Target: net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))),
		conn:   conn,
	}, nil
}

// greet reads the version identifier and selects a method.
//
// Only "no authentication" is offered. The proxy this fronts listens on
// loopback for processes that are already inside the sandbox, so a password
// would prove nothing that reaching the port has not already proved.
func greet(conn net.Conn) error {
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return fmt.Errorf("socks5: read greeting: %w", err)
	}
	if head[0] != Version {
		// Worth naming: something pointed at this port speaking another
		// protocol entirely is the likely cause, not a broken SOCKS client.
		return fmt.Errorf("socks5: greeting version %#x, want %#x (is this a SOCKS5 client?)", head[0], Version)
	}

	methods := make([]byte, head[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("socks5: read auth methods: %w", err)
	}
	for _, m := range methods {
		if m == MethodNoAuth {
			if _, err := conn.Write([]byte{Version, MethodNoAuth}); err != nil {
				return fmt.Errorf("socks5: write method selection: %w", err)
			}
			return nil
		}
	}

	conn.Write([]byte{Version, MethodNoAcceptable})
	return errors.New("socks5: client offered no authentication method this proxy accepts")
}

var (
	errAddrType  = errors.New("socks5: unsupported address type")
	errBadDomain = errors.New("socks5: domain name is not a hostname")
)

// isHostname reports whether the domain field holds something that is actually
// a name.
//
// The field is 255 arbitrary bytes and nothing downstream re-checks them: they
// become the hostname the allowlist is matched against, the request line and
// Host header of the CONNECT the router writes into the tunnel, and a line in
// the log. A client that can put a CRLF in a hostname can write a second
// request inside the first, and a wildcard route is enough to make such a name
// match — so the characters a hostname may contain are checked here, once,
// where the bytes come in.
//
// Deliberately a little wider than the letter of RFC 1123: underscores appear
// in real service-discovery names, and a single trailing dot is how a fully
// qualified name is written. Anything non-ASCII is refused rather than guessed
// at — an IDNA-aware client sends punycode, which is ASCII.
func isHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return false
	}
	for label := range strings.SplitSeq(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			case c == '-' || c == '_':
			default:
				return false
			}
		}
	}
	return true
}

func readAddress(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case AddrIPv4:
		var b [4]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return "", fmt.Errorf("socks5: read IPv4 address: %w", err)
		}
		return net.IP(b[:]).String(), nil

	case AddrIPv6:
		var b [16]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return "", fmt.Errorf("socks5: read IPv6 address: %w", err)
		}
		return net.IP(b[:]).String(), nil

	case AddrDomain:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return "", fmt.Errorf("socks5: read domain length: %w", err)
		}
		b := make([]byte, n[0])
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", fmt.Errorf("socks5: read domain: %w", err)
		}
		host := string(b)
		if !isHostname(host) {
			return "", fmt.Errorf("%w: %q", errBadDomain, host)
		}
		return host, nil

	default:
		return "", fmt.Errorf("%w: %#x", errAddrType, atyp)
	}
}

// Grant tells the client the connection is up; everything after it is the
// tunnelled traffic.
func (r *Request) Grant() error { return reply(r.conn, RepSuccess) }

// Refuse answers with a failure code and leaves the connection for the caller
// to close.
func (r *Request) Refuse(code byte) error { return reply(r.conn, code) }

// reply writes a SOCKS5 reply with a zero bound address.
//
// The bound address is what the proxy would be reachable at for this
// connection, and a client that already knows where it dialled has no use for
// it — curl, Go's own dialer and every library worth naming ignore the field.
// Sending 0.0.0.0:0 keeps that honest instead of inventing an address.
func reply(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{Version, code, 0x00, AddrIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// ReplyCode maps a dial error to the reply that describes it best. Anything
// this cannot recognise is "host unreachable", which is the truthful answer
// when the proxy could not reach the target and does not know why.
func ReplyCode(err error) byte {
	if err == nil {
		return RepSuccess
	}
	if strings.Contains(err.Error(), "connection refused") {
		return RepConnRefused
	}
	return RepHostUnreachable
}
