package vtunnel

// The sandbox egress proxy answers CONNECT over HTTP/2 as well as HTTP/1.1, and the
// two are served by completely different code: one hijacks a socket, the other
// pipes a stream through the ResponseWriter.

import (
	"net"
	"testing"
)

// The sandbox egress proxy answers CONNECT over HTTP/2 as well as HTTP/1.1, and the
// two are served by completely different code: one hijacks a socket, the other
// pipes a stream through the ResponseWriter. Only the HTTP/1.1 half was covered.
func TestEgressServesHTTP2Connect(t *testing.T) {
	backend := startRawEchoListener(t)

	egress := newEgressProxy()
	if err := egress.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer egress.Close()

	if egress.Addr() == nil {
		t.Fatal("Addr is nil after Start")
	}

	conn := h2ConnectTunnel(t, egress.Addr().String(), backend)
	assertEchoTunnel(t, conn, "egress h2 connect")
}

// The same over a chained CONNECT: the egress proxy forwards to the controlplane
// proxy, so the HTTP/2 stream is spliced to a connection the egress proxy opened
// rather than to the host itself.
func TestEgressChainsHTTP2Connect(t *testing.T) {
	backend := startRawEchoListener(t)

	// Stands in for the controlplane: answers CONNECT and pipes to the backend.
	chained := newEgressProxy()
	if err := chained.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("chained Start: %v", err)
	}
	defer chained.Close()

	egress := newEgressProxy()
	if err := egress.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer egress.Close()

	chainPort := chained.Addr().(*net.TCPAddr).Port
	egress.SetRoutes(chainPort, []string{backend})

	conn := h2ConnectTunnel(t, egress.Addr().String(), backend)
	assertEchoTunnel(t, conn, "egress h2 chained connect")
}
