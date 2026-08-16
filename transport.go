package vtunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"

	"github.com/gorilla/websocket"

	"github.com/vivid-money/vtunnel/internal/transport/tcp"
	"github.com/vivid-money/vtunnel/internal/transport/ws"
)

// The transport is whatever carries bytes between the two ends: a dialling
// half and an accepting half, both dealing in net.Conn and nothing else.
//
// It contributes nothing to security. The session on top authenticates and
// encrypts either way, so ws:// and tcp:// are equally safe and neither is
// trusted. Which one to use is a networking question — what can reach the
// sandbox — not a security one.
//
// Both halves are chosen by URL scheme, so the two ends read the same way:
//
//	// sandbox
//	ln, err := vtunnel.Listen("tcp://:3001")
//	go vtunnel.Serve(ln, server)
//
//	// controlplane
//	client := vtunnel.NewClient("tcp://sandbox:3001", vtunnel.WithSecret(secret))
//
// Supported schemes are ws, wss and tcp. Anything else is a job for
// [WithDialer] and a [net.Listener] of your own.

// Dialer opens the transport a client runs its tunnel over.
//
// Anything that can produce an ordered byte stream will do. Wrapping one is
// the way to add behaviour the tunnel has no opinion about — a proxy, a
// retry, artificial latency for a benchmark:
//
//	base, _ := vtunnel.NewDialer("ws://sandbox:3001/", nil)
//	slow := func(ctx context.Context) (net.Conn, error) {
//	    conn, err := base(ctx)
//	    return delayed(conn), err
//	}
type Dialer func(ctx context.Context) (net.Conn, error)

// NewDialer returns the dialer for a tunnel URL. headers are sent with the
// WebSocket handshake and ignored by every other scheme.
func NewDialer(tunnelURL string, headers http.Header) (Dialer, error) {
	scheme, addr, _, err := splitTunnelURL(tunnelURL)
	if err != nil {
		return nil, err
	}
	switch scheme {
	case "ws", "wss":
		return func(ctx context.Context) (net.Conn, error) {
			return ws.Dial(ctx, tunnelURL, headers, defaultHandshakeTimeout)
		}, nil
	case "tcp":
		return func(ctx context.Context) (net.Conn, error) {
			return tcp.Dial(ctx, addr, defaultDialTimeout)
		}, nil
	default:
		return nil, fmt.Errorf("vtunnel: unsupported transport %q in %q (want ws, wss or tcp)", scheme, tunnelURL)
	}
}

// Listen accepts tunnel connections for a URL, and is the accepting half of
// whatever [NewDialer] would dial. Hand the result to [Serve].
//
// The host part is a bind address, so "tcp://:3001" and "ws://127.0.0.1:3001/"
// both work. wss is not accepted here: terminating TLS needs a certificate and
// belongs to whatever is already doing it — the session authenticates the peer
// regardless, so there is nothing lost by putting a proxy in front.
func Listen(tunnelURL string) (net.Listener, error) {
	scheme, addr, path, err := splitTunnelURL(tunnelURL)
	if err != nil {
		return nil, err
	}
	switch scheme {
	case "ws":
		return ws.Listen(addr, path, defaultHandshakeTimeout)
	case "tcp":
		return tcp.Listen(addr)
	case "wss":
		return nil, fmt.Errorf("vtunnel: cannot listen on %q: terminate TLS in front and listen on ws:// behind it", tunnelURL)
	default:
		return nil, fmt.Errorf("vtunnel: unsupported transport %q in %q (want ws or tcp)", scheme, tunnelURL)
	}
}

// Serve hands every connection ln accepts to srv, and returns when ln stops
// accepting. Each connection is served on its own goroutine and lives until
// the client on the other end goes away.
func Serve(ln net.Listener, srv *Server) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go srv.HandleConn(conn)
	}
}

func splitTunnelURL(raw string) (scheme, addr, path string, err error) {
	u, parseErr := url.Parse(raw)
	if parseErr != nil {
		return "", "", "", fmt.Errorf("vtunnel: bad tunnel URL %q: %w", raw, parseErr)
	}
	if u.Scheme == "" {
		return "", "", "", fmt.Errorf("vtunnel: tunnel URL %q has no scheme (want ws://, wss:// or tcp://)", raw)
	}
	return u.Scheme, u.Host, u.Path, nil
}

// NewUpgrader returns a websocket.Upgrader configured for tunnel traffic.
//
// Reach for it, with [NewWSConn] and [Server.HandleConn], when the tunnel has
// to share an HTTP mux with something else. [Listen] is the shorter path when
// it does not.
func NewUpgrader() websocket.Upgrader { return ws.Upgrader(defaultHandshakeTimeout) }

// NewWSConn presents a *websocket.Conn as a net.Conn, ready for
// [Server.HandleConn].
func NewWSConn(conn *websocket.Conn) net.Conn { return ws.Conn(conn) }

// pipe copies bidirectionally between a and b, and closes both when both
// directions are done. Blocks until then.
//
// Each direction ends on its own. A clean end of one is forwarded as a
// half-close — "nothing more is coming from this side" — and the other
// direction goes on. Closing both on the first EOF instead, which is the
// obvious way to write this, silently truncates every request/response
// exchange where the caller shuts down its write side before reading the
// answer: curl --http1.0, git over a plain forward, and the sandbox router
// itself, whose dualStream half-closes the tunnel socket the moment the
// application has finished its request.
//
// An error is not a half-close: the pipe is already broken, so that side is
// closed outright rather than left waiting for a peer that will never answer.
// A stream that cannot half-close at all is closed for the same reason — an
// abrupt end beats a hang.
func pipe(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	half := func(dst, src io.ReadWriteCloser) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		if err == nil {
			if cw, ok := dst.(closeWriter); ok && cw.CloseWrite() == nil {
				return
			}
		}
		dst.Close()
	}
	wg.Add(2)
	go half(a, b)
	go half(b, a)
	wg.Wait()

	a.Close()
	b.Close()
}

// setTCPOptions enables keepalive and disables Nagle on TCP connections.
func setTCPOptions(conn net.Conn) { tcp.SetOptions(conn) }
