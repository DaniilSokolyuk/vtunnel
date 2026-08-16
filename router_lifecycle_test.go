package vtunnel

import (
	"sync"
	"testing"
)

// The same unguarded Start/Addr/Close as the MITM proxy, in miniature.
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
