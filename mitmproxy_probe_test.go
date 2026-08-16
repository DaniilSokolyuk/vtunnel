package vtunnel

// The h2c probe, and the certificate cache under pressure.

import (
	"crypto/tls"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// The probe dials the target and waits for a SETTINGS frame, and it does that
// on the request path — through the whole tunnel, for a tunnelled target. Every
// concurrent request for a target nobody has probed yet used to start its own:
// a burst of ten requests meant ten dials, ten waits, and up to eight seconds
// of nothing each while they all learned the same fact.
func TestH2CProbeIsSharedBetweenConcurrentRequests(t *testing.T) {
	var mu sync.Mutex
	accepted := 0

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			accepted++
			mu.Unlock()
			go func() {
				defer conn.Close()
				buf := make([]byte, len("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
				if _, err := conn.Read(buf); err != nil {
					return
				}
				// An empty SETTINGS frame: type 0x04, no payload.
				conn.Write([]byte{0, 0, 0, 0x04, 0, 0, 0, 0, 0})
				time.Sleep(50 * time.Millisecond) // hold the probe open a moment
			}()
		}
	}()

	p := NewMITMProxy()
	target := ln.Addr().String()

	var wg sync.WaitGroup
	results := make([]bool, 8)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = p.probeH2C(target)
		}()
	}
	wg.Wait()

	for i, ok := range results {
		if !ok {
			t.Fatalf("probe %d reported no h2c for a target that answered with SETTINGS", i)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if accepted != 1 {
		t.Fatalf("the target was probed %d times for one answer: concurrent requests each "+
			"ran their own probe, and each of them blocks the request behind it", accepted)
	}
}

// A full cache used to be emptied wholesale, so a client walking a thousand SNI
// names cost every other client on the proxy a fresh keygen per handshake.
// Eviction should cost the oldest entries, not all of them.
func TestFullCertCacheEvictsPartially(t *testing.T) {
	if testing.Short() {
		t.Skip("generates a cacheful of keys")
	}

	cache, err := newCertCache(testCA(t, "eviction CA"))
	if err != nil {
		t.Fatalf("newCertCache: %v", err)
	}

	now := time.Now()
	// Fill it to the brim with entries that are all still fresh, which is the
	// case the old sweep could do nothing with.
	for i := range maxCachedCerts {
		cache.certs[hostName(i)] = &cachedCert{
			cert: &tls.Certificate{},
			// All comfortably fresh: the case the old sweep could free nothing
			// in, and answered by dropping the lot.
			renewAt: now.Add(time.Hour + time.Duration(i)*time.Second),
		}
	}

	cache.mu.Lock()
	cache.sweepLocked(now)
	remaining := len(cache.certs)
	_, oldestSurvived := cache.certs[hostName(0)]
	_, newestSurvived := cache.certs[hostName(maxCachedCerts-1)]
	cache.mu.Unlock()

	if remaining == 0 {
		t.Fatal("a full cache of fresh entries was dropped wholesale: every live connection " +
			"now pays for a new key on its next handshake")
	}
	if remaining >= maxCachedCerts {
		t.Fatalf("the sweep freed nothing (%d entries left of %d)", remaining, maxCachedCerts)
	}
	if oldestSurvived {
		t.Error("the oldest entry survived; eviction should start there")
	}
	if !newestSurvived {
		t.Error("the newest entry was evicted; it is the one most likely to be wanted again")
	}
}

func hostName(i int) string {
	return "host-" + strconv.Itoa(i) + ".test"
}
