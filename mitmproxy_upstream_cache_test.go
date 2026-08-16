package vtunnel

// What the proxy remembers about an upstream, and for how long.

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// h2cSwitch is a listener whose answer to the h2 preface is decided by a flag,
// so a test can redeploy it mid-run.
func h2cSwitch(t *testing.T, speaksH2C *atomic.Bool) string {
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
				buf := make([]byte, 24)
				conn.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := conn.Read(buf); err != nil {
					return
				}
				if speaksH2C.Load() {
					// An empty SETTINGS frame: length 0, type 0x04.
					conn.Write([]byte{0, 0, 0, 0x04, 0, 0, 0, 0, 0})
					return
				}
				conn.Write([]byte("HTTP/1.1 505 HTTP Version Not Supported\r\n\r\n"))
			}()
		}
	}()
	return ln.Addr().String()
}

// What was learned about an upstream is learned about an upstream as it was.
// A backend that gains or loses h2c across a redeploy keeps its address, so an
// answer with no expiry pinned it to the wrong protocol until the process
// restarted — while noMITM, which learns exactly the same kind of fact, has
// expired its own for precisely this reason.
func TestUpstreamProbesExpire(t *testing.T) {
	defer func(previous time.Duration) { probeTTL = previous }(probeTTL)
	probeTTL = 100 * time.Millisecond

	var speaksH2C atomic.Bool
	target := h2cSwitch(t, &speaksH2C)

	p := NewMITMProxy()
	if p.probeH2C(target) {
		t.Fatal("the target does not speak h2c yet")
	}

	speaksH2C.Store(true)
	if p.probeH2C(target) {
		t.Fatal("the answer must be remembered until it expires")
	}

	time.Sleep(2 * probeTTL)
	if !p.probeH2C(target) {
		t.Fatal("the answer never expired: an upstream that changed protocol is " +
			"unreachable until the process restarts")
	}
}

// A route that is withdrawn takes its pooled upstream connections with it.
// Leaving them behind kept a socket and its read goroutine alive for a target
// nothing routes to any more.
func TestRemovingARouteDropsItsUpstreamTransport(t *testing.T) {
	backend := echoBackend(t)

	p := NewMITMProxy()
	if err := p.ForwardTo("api.corp", backend); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	// Build a transport for it the way a request would.
	rt, _ := p.resolveDomain("api.corp:443")
	transport, _, release := p.upstreamTransport(rt, nil, false)
	release()
	if transport == nil {
		t.Fatal("no transport was built")
	}

	p.upstreamsMu.Lock()
	before := len(p.upstreams)
	p.upstreamsMu.Unlock()
	if before == 0 {
		t.Skip("this route's transport is the shared one, nothing to evict")
	}

	p.Remove("api.corp")

	p.upstreamsMu.Lock()
	after := len(p.upstreams)
	p.upstreamsMu.Unlock()
	if after != 0 {
		t.Fatalf("%d cached upstream transport(s) survived Remove", after)
	}
}
