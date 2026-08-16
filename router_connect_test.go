package vtunnel

// The sandbox router answers CONNECT over HTTP/2 as well as HTTP/1.1, and the
// two are served by completely different code: one hijacks a socket, the other
// pipes a stream through the ResponseWriter.

import (
	"net"
	"testing"
)

// The sandbox router answers CONNECT over HTTP/2 as well as HTTP/1.1, and the
// two are served by completely different code: one hijacks a socket, the other
// pipes a stream through the ResponseWriter. Only the HTTP/1.1 half was covered.
func TestRouterServesHTTP2Connect(t *testing.T) {
	backend := startRawEchoListener(t)

	router := newRouter()
	if err := router.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer router.Close()

	if router.Addr() == nil {
		t.Fatal("Addr is nil after Start")
	}

	conn := h2ConnectTunnel(t, router.Addr().String(), backend)
	assertEchoTunnel(t, conn, "router h2 connect")
}

// The same over a chained CONNECT: the router forwards to the controlplane
// proxy, so the HTTP/2 stream is spliced to a connection the router opened
// rather than to the host itself.
func TestRouterChainsHTTP2Connect(t *testing.T) {
	backend := startRawEchoListener(t)

	// Stands in for the controlplane: answers CONNECT and pipes to the backend.
	chained := newRouter()
	if err := chained.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("chained Start: %v", err)
	}
	defer chained.Close()

	router := newRouter()
	if err := router.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer router.Close()

	chainPort := chained.Addr().(*net.TCPAddr).Port
	router.SetRoutes(chainPort, []string{backend})

	conn := h2ConnectTunnel(t, router.Addr().String(), backend)
	assertEchoTunnel(t, conn, "router h2 chained connect")
}
