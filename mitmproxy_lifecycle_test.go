package vtunnel

import (
	"sync"
	"testing"
)

// Start installs the listener and the shutdown plumbing while Addr, Close and
// Shutdown read them from other goroutines. Writing those fields bare was a
// race, and reassigning the sync.Once overwrote the mutex inside it — possibly
// while another goroutine held it.
//
// CI runs the tests without -race, so none of this would have surfaced there.
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
