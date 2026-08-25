package vtunnel_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

// Close used to stop the listener and nothing else. Everything a CONNECT had
// spawned outlived it: the connection itself, the nested http.Server or
// http2.Server serving the decrypted stream, and the goroutines and file
// descriptors both hold. In a test binary that showed up as leaked goroutines;
// in the CLI it meant the process would not come down cleanly.
//
// These tests exercise Close and Shutdown through the public API, so what they
// pin down is the observable contract rather than the bookkeeping behind it.

// Close must reach a connection that is mid-response, not just the listener.
func TestMITMProxyCloseDropsLiveConnection(t *testing.T) {
	serving := make(chan struct{})
	release := make(chan struct{})
	defer close(release)

	proxy, proxyAddr := startSSEProxy(t, true, nil)
	proxy.Handle("hang.test:443", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		http.NewResponseController(w).Flush()
		close(serving)
		<-release // hold the response open until the test is done with it
	}))

	client := sseProxyClient(t, proxyAddr, false)
	resp, err := client.Get("https://hang.test/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	select {
	case <-serving:
	case <-time.After(5 * time.Second):
		t.Fatal("handler never started")
	}

	proxy.Close()

	// The body read must fail rather than hang: the connection is gone.
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(resp.Body)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("reading the body succeeded after Close; the connection survived")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("body read still blocked 5s after Close; the connection survived")
	}
}

// The regression signal for the whole class of leak: once Close returns, nothing
// the proxy started should still be running.
func TestMITMProxyCloseLeavesNoGoroutines(t *testing.T) {
	backend := sseBackend(t, "leak")

	settle(t)
	before := runtime.NumGoroutine()

	proxy, proxyAddr := startSSEProxy(t, true, nil)
	proxy.ForwardTo("leak.test:443", backend.Listener.Addr().String())

	// Several connections, so the nested servers and their conns really exist.
	client := sseProxyClient(t, proxyAddr, false)
	for range 3 {
		resp, err := client.Get("https://leak.test/")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	proxy.Close()

	// Goroutines wind down asynchronously, so this is a bounded wait rather than
	// a single sample. The tolerance covers the test client's own transport.
	deadline := time.Now().Add(5 * time.Second)
	var after int
	for time.Now().Before(deadline) {
		runtime.GC()
		after = runtime.NumGoroutine()
		if after <= before+2 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("goroutines %d -> %d after Close; the proxy left work running", before, after)
}

// Shutdown differs from Close by letting a request that already started finish.
func TestMITMProxyShutdownWaitsForInflightRequest(t *testing.T) {
	serving := make(chan struct{})

	proxy, proxyAddr := startSSEProxy(t, true, nil)
	proxy.Handle("slow.test:443", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(serving)
		time.Sleep(300 * time.Millisecond)
		io.WriteString(w, "finished")
	}))

	client := sseProxyClient(t, proxyAddr, false)

	type result struct {
		body string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := client.Get("https://slow.test/")
		if err != nil {
			done <- result{err: err}
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		done <- result{body: string(body), err: err}
	}()

	select {
	case <-serving:
	case <-time.After(5 * time.Second):
		t.Fatal("handler never started")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := proxy.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	got := <-done
	if got.err != nil {
		t.Fatalf("the in-flight request did not survive Shutdown: %v", got.err)
	}
	if got.body != "finished" {
		t.Fatalf("body = %q, want the complete response", got.body)
	}
}

// A request that never ends must not hold Shutdown forever: the deadline wins
// and says so.
func TestMITMProxyShutdownHonoursDeadline(t *testing.T) {
	serving := make(chan struct{})
	release := make(chan struct{})
	defer close(release)

	proxy, proxyAddr := startSSEProxy(t, true, nil)
	proxy.Handle("stuck.test:443", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		http.NewResponseController(w).Flush()
		close(serving)
		<-release
	}))

	client := sseProxyClient(t, proxyAddr, false)
	resp, err := client.Get("https://stuck.test/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	select {
	case <-serving:
	case <-time.After(5 * time.Second):
		t.Fatal("handler never started")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = proxy.Shutdown(ctx)
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("Shutdown took %v; it did not give up at the deadline", elapsed)
	}
}

// An SSE stream is an in-flight request that never finishes on its own, which is
// the case Shutdown's "wait for in-flight requests" contract cannot honour. Two
// things have to hold anyway, and neither is obvious from the code:
//
//   - Shutdown must give up at the deadline instead of waiting on a stream that
//     will still be open tomorrow.
//   - The upstream must learn about it. The proxy sits between two connections
//     and only closes the client one; nothing unwinds the upstream unless the
//     cancellation travels the whole chain — client connection closed, nested
//     server cancels the handler's request context, http.Transport aborts the
//     round trip, the response body errors out and gets closed, and only then
//     does the upstream see its own request cancelled. A break anywhere in that
//     chain leaves a real LLM API streaming tokens into nothing, still billing
//     for them.
func TestMITMProxyShutdownCancelsLiveSSEUpstream(t *testing.T) {
	const preShutdownEvents = 3

	streaming := make(chan struct{})
	upstreamCancelled := make(chan struct{})
	teardown := make(chan struct{})

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)

		for i := range preShutdownEvents {
			fmt.Fprintf(w, "data: pre-%d\n\n", i)
			if err := rc.Flush(); err != nil {
				return
			}
		}
		close(streaming)

		// Then hold the stream open with nothing more to send, the way an idle
		// LLM stream sits between tokens.
		select {
		case <-r.Context().Done():
			close(upstreamCancelled)
		case <-teardown:
			// Only reached when the assertion below has already failed. Without
			// it httptest.Server.Close would block on this handler forever and
			// the failure would surface as a test-binary timeout instead of the
			// message that explains it.
		}
	}))
	// Cleanups run last-registered-first, so teardown is signalled before the
	// server waits for its outstanding requests.
	t.Cleanup(backend.Close)
	t.Cleanup(func() { close(teardown) })

	proxy, proxyAddr := startSSEProxy(t, true, nil)
	proxy.ForwardTo("stream.test:443", backend.Listener.Addr().String())

	client := sseProxyClient(t, proxyAddr, false)
	resp, err := client.Get("https://stream.test/v1/messages")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	// Everything pushed before the shutdown has to have arrived, so what follows
	// is about tearing down a working stream rather than a broken one.
	collectSSE(t, resp.Body, preShutdownEvents)

	select {
	case <-streaming:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never reached the idle part of the stream")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = proxy.Shutdown(ctx)
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown err = %v, want context.DeadlineExceeded — an open SSE stream never drains", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("Shutdown blocked for %v on a stream that never ends", elapsed)
	}

	select {
	case <-upstreamCancelled:
	case <-time.After(10 * time.Second):
		t.Fatal("the upstream request was never cancelled: the shutdown stopped at the client " +
			"connection and left the upstream streaming into a closed proxy")
	}

	// And the client's end of the stream must break rather than hang.
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(resp.Body)
		done <- err
	}()
	select {
	case <-done: // any outcome is fine, EOF included; hanging is not
	case <-time.After(5 * time.Second):
		t.Fatal("the client's stream never ended after Shutdown")
	}
}

// Lifecycle calls must be safe in any order and any number of times — a caller
// wiring this up with defer should not have to reason about it.
func TestMITMProxyLifecycleIsIdempotent(t *testing.T) {
	unstarted := vtunnel.NewMITMProxy()
	unstarted.Close() // before Start: must not panic on the nil listener
	if err := unstarted.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown before Start: %v", err)
	}

	proxy, _ := startSSEProxy(t, true, nil)
	proxy.Close()
	proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := proxy.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown after Close: %v", err)
	}
}

// Once shutting down, a fresh CONNECT must be refused rather than opening a
// connection that would outlive the shutdown that is already under way.
func TestMITMProxyRefusesConnectWhileShuttingDown(t *testing.T) {
	proxy, proxyAddr := startSSEProxy(t, true, nil)
	proxy.ForwardTo("late.test:443", "127.0.0.1:1")

	proxy.Close()

	client := sseProxyClient(t, proxyAddr, false)
	client.Timeout = 3 * time.Second
	if _, err := client.Get("https://late.test/"); err == nil {
		t.Fatal("CONNECT succeeded after Close")
	}
}

// settle waits for background goroutines from earlier work to wind down, so the
// baseline a leak check compares against is not inflated by them.
func settle(t *testing.T) {
	t.Helper()
	for range 20 {
		runtime.GC()
		time.Sleep(25 * time.Millisecond)
	}
}
