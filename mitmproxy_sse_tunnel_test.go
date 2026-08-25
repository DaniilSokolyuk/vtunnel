package vtunnel_test

import (
	"bufio"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

// TestProxyHTTP_SSEStreamsEventByEvent is a regression test for a buffering
// bug in proxyHandler.handleHTTP. The plain-HTTP proxy path used to copy the
// upstream response with `io.Copy(w, resp.Body)`, which leaves the
// http.ResponseWriter's bufio writer un-flushed between events. As a result,
// SSE responses (text/event-stream) — Anthropic streaming, OpenAI streaming,
// any LLM proxy traffic — arrive at the client in one batch only after the
// upstream has fully emitted the body, instead of event-by-event.
//
// Symptom in production: agents that depend on incremental SSE events
// (tool_use deltas, content_block_start/stop) think the response finished
// without actionable content blocks and stop calling the next tool.
//
// The fix is to use flushingCopy (same helper already used for CONNECT
// streams in dualStream).
func TestProxyHTTP_SSEStreamsEventByEvent(t *testing.T) {
	const (
		eventCount = 5
		eventGap   = 80 * time.Millisecond
	)

	// Upstream emits an SSE event every eventGap. If the proxy passes the
	// body through with per-Write flushing, the client should see each event
	// roughly when it was emitted upstream.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Errorf("upstream: ResponseWriter is not a Flusher")
			return
		}
		for i := 0; i < eventCount; i++ {
			if _, err := fmt.Fprintf(w, "data: event-%d\n\n", i); err != nil {
				return
			}
			flusher.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(eventGap):
			}
		}
	}))
	defer backend.Close()

	ts, server := startTunnelServer(t)
	defer ts.Close()

	proxyPort := freePort(t)
	if err := server.StartProxy(fmt.Sprintf("127.0.0.1:%d", proxyPort)); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	client := vtunnel.NewClient(wsURL(ts))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	client.Proxy().ForwardTo("sse.test", backend.Listener.Addr().String())
	time.Sleep(200 * time.Millisecond)

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	httpClient := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			DisableKeepAlives: true,
		},
	}

	start := time.Now()
	resp, err := httpClient.Get("http://sse.test/v1/messages")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type: %q (want text/event-stream)", ct)
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var arrivals []time.Duration
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			arrivals = append(arrivals, time.Since(start))
			if len(arrivals) == eventCount {
				break
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(arrivals) != eventCount {
		t.Fatalf("got %d events, want %d", len(arrivals), eventCount)
	}

	// Without per-write flushing in handleHTTP, all events arrive in a
	// single batch right after the upstream finishes (≈ eventCount*eventGap).
	// With the fix, event 0 should land within ~one gap of t=0.
	maxFirstArrival := 2 * eventGap
	if arrivals[0] > maxFirstArrival {
		t.Fatalf("event 0 arrived after %v (max %v) — proxy is buffering SSE; full timing: %v",
			arrivals[0], maxFirstArrival, arrivals)
	}
	// Each subsequent event should follow within roughly one gap.
	for i := 1; i < len(arrivals); i++ {
		delta := arrivals[i] - arrivals[i-1]
		if delta > 4*eventGap {
			t.Fatalf("event %d arrived %v after event %d (>4×gap=%v); full timing: %v",
				i, delta, i-1, 4*eventGap, arrivals)
		}
	}
}
