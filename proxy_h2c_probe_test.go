package vtunnel

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
)

// probeH2C dials and round-trips through the whole tunnel, so a transient
// failure (tunnel reconnecting, slow hop) is not evidence the target can't do
// h2c. A transient failure must not be cached, or the target is pinned to
// HTTP/1.1 until the proxy restarts and gRPC over it breaks forever.
func TestProbeH2CDoesNotCacheTransientFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var attempts int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn, n int32) {
				defer c.Close()
				// Consume the client's HTTP/2 preface (24 bytes).
				io.ReadFull(c, make([]byte, 24))
				if n == 1 {
					// Transient: drop the connection with no response, as a
					// mid-reconnect tunnel would.
					return
				}
				// Healthy: reply with an empty SETTINGS frame (type 0x04).
				c.Write([]byte{0, 0, 0, 0x04, 0, 0, 0, 0, 0})
			}(conn, atomic.AddInt32(&attempts, 1))
		}
	}()

	h := &proxyHandler{}
	target := ln.Addr().String()

	if h.probeH2C(target) {
		t.Fatal("first probe hit a transient failure and must report not-h2c")
	}
	if _, cached := h.h2cProbed.Load(target); cached {
		t.Fatal("transient failure must not be cached")
	}

	if !h.probeH2C(target) {
		t.Fatal("second probe must detect h2c once the target responds")
	}
	if v, cached := h.h2cProbed.Load(target); !cached || v.(bool) != true {
		t.Fatalf("deterministic h2c result must be cached true, got cached=%v v=%v", cached, v)
	}
}
