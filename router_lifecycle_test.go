package vtunnel

// The sandbox router's lifecycle. Everything here is about what "the proxy is
// stopped" means: a listener nothing can close, and tunnels that keep relaying
// after Close returned, are both ways of it not being true.

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func echoBackend(t *testing.T) string {
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
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// openConnectTunnel opens a CONNECT tunnel through the router to target.
func openConnectTunnel(t *testing.T, routerAddr, target string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", routerAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: %s", resp.Status)
	}
	return conn
}

// openSocksTunnel does the same through the SOCKS5 front end.
func openSocksTunnel(t *testing.T, routerAddr, host string, port int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", routerAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	conn.Write([]byte{5, 1, 0})
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatalf("socks greeting: %v", err)
	}
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	conn.Write(req)
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("socks reply: %v", err)
	}
	if reply[1] != 0 {
		t.Fatalf("socks refused with %#x", reply[1])
	}
	conn.SetDeadline(time.Time{})
	return conn
}

func stillRelaying(t *testing.T, conn net.Conn) bool {
	t.Helper()
	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte("ping\n")); err != nil {
		return false
	}
	answer := make([]byte, 5)
	_, err := io.ReadFull(conn, answer)
	return err == nil && string(answer) == "ping\n"
}

// Close is documented as reaching connections already established, "a CONNECT
// tunnel mid-transfer" among them. It reached neither of the two things the
// router is mostly made of: net/http stops tracking a connection the moment it
// is hijacked, and a SOCKS5 connection never passes through net/http at all. So
// stopping the sandbox proxy left every tunnel it had opened still relaying,
// each holding a socket out of the sandbox.
func TestRouterCloseEndsHijackedTunnels(t *testing.T) {
	backend := echoBackend(t)
	_, port, _ := net.SplitHostPort(backend)

	r := newRouter()
	if err := r.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	routerAddr := r.Addr().String()

	connect := openConnectTunnel(t, routerAddr, backend)
	if !stillRelaying(t, connect) {
		t.Fatal("the CONNECT tunnel does not work to begin with")
	}

	var socksPort int
	fmt.Sscanf(port, "%d", &socksPort)
	socks := openSocksTunnel(t, routerAddr, "localhost", socksPort)
	if !stillRelaying(t, socks) {
		t.Fatal("the SOCKS5 tunnel does not work to begin with")
	}

	r.Close()
	time.Sleep(200 * time.Millisecond)

	if stillRelaying(t, connect) {
		t.Error("the CONNECT tunnel is still relaying after Close")
	}
	if stillRelaying(t, socks) {
		t.Error("the SOCKS5 tunnel is still relaying after Close")
	}
}

// Close before Start used to spend the once on a listener that did not exist
// yet, so the Start that followed installed one nothing could ever close. The
// proxy has the same guard, added for the same reason.
func TestRouterCloseBeforeStartStillArmsTheGuard(t *testing.T) {
	r := newRouter()
	r.Close()

	if err := r.Start("127.0.0.1:0"); err == nil {
		addr := r.Addr().String()
		r.Close()
		time.Sleep(100 * time.Millisecond)
		conn, dialErr := net.DialTimeout("tcp", addr, time.Second)
		if dialErr == nil {
			conn.Close()
		}
		t.Fatalf("Start after Close was accepted (listener on %s, still accepting: %v)", addr, dialErr == nil)
	}
}

// A second Start used to overwrite the first listener, leaving it accepting
// with nobody holding a reference to close it.
func TestRouterRefusesASecondStart(t *testing.T) {
	r := newRouter()
	if err := r.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	first := r.Addr().String()
	defer r.Close()

	if err := r.Start("127.0.0.1:0"); err == nil {
		t.Fatal("a second Start was accepted, orphaning the first listener")
	}
	if r.Addr().String() != first {
		t.Fatalf("Addr changed to %s after a refused Start", r.Addr())
	}
}

// The router's own transport had none of the bounds the proxy's has: a dial
// with no timeout at all, and idle connections that never expire — one leak per
// distinct host a sandbox application touches over cleartext.
func TestRouterTransportIsBounded(t *testing.T) {
	r := newRouter()
	if r.transport.DialContext == nil {
		t.Error("the router's transport dials with no timeout")
	}
	if r.transport.IdleConnTimeout == 0 {
		t.Error("the router's transport keeps idle connections forever")
	}
}

// A black-holed cleartext request answers within the dial timeout instead of
// hanging until the client gives up.
func TestRouterCleartextDialIsBounded(t *testing.T) {
	r := newRouter()
	if err := r.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer r.Close()

	conn, err := net.DialTimeout("tcp", r.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(dialTimeout + 10*time.Second))

	// 192.0.2.0/24 is reserved for documentation and routes nowhere.
	fmt.Fprint(conn, "GET http://192.0.2.1/ HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n")
	start := time.Now()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no answer after %v: %v", time.Since(start), err)
	}
	resp.Body.Close()
	if elapsed := time.Since(start); elapsed > dialTimeout+5*time.Second {
		t.Fatalf("the answer took %v; the dial is unbounded", elapsed)
	}
}
