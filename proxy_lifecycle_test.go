package vtunnel

// Start installs the listener and the shutdown plumbing while Addr, Close and
// Shutdown read them from other goroutines. Writing those fields bare was a
// race, and reassigning the sync.Once overwrote the mutex inside it — possibly
// while another goroutine held it.
//
// CI runs the tests without -race, so nothing here would have surfaced there.

import (
	"sync"
	"testing"
)

func TestProxyLifecycleIsRaceFree(t *testing.T) {
	for range 20 {
		p := NewMITMProxy()

		var wg sync.WaitGroup
		wg.Add(3)
		go func() { defer wg.Done(); p.Start("127.0.0.1:0") }()
		go func() { defer wg.Done(); p.Addr() }()
		go func() { defer wg.Done(); p.Close() }()
		wg.Wait()

		p.Close() // whichever order the three landed in, nothing is left listening
	}
}

func TestRouterLifecycleIsRaceFree(t *testing.T) {
	for range 20 {
		r := newRouter()

		var wg sync.WaitGroup
		wg.Add(3)
		go func() { defer wg.Done(); r.Start("127.0.0.1:0") }()
		go func() { defer wg.Done(); r.Addr() }()
		go func() { defer wg.Done(); r.Close() }()
		wg.Wait()

		r.Close()
	}
}
