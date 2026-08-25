package vtunnel

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The trailer announcement was written into the header map and then deleted by
// removeHopByHop inside copyResponse, before WriteHeader — Trailer is itself
// hop-by-hop. The loop that wrote it did nothing at all, and only the
// unannounced TrailerPrefix path kept gRPC working.
func TestTrailerAnnouncementSurvivesToTheClient(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "body")
		w.Header().Set("Grpc-Status", "0")
	}))
	defer upstream.Close()

	proxy, proxyAddr, ca := startCoverageProxy(t, nil)
	proxy.ForwardTo("trailers.test:443", upstream.Listener.Addr().String())

	resp, err := coverageClient(proxyAddr, ca, true).Get("https://trailers.test/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	// Announced before the body: the client sees the name in Trailer up front.
	if _, ok := resp.Trailer["Grpc-Status"]; !ok {
		t.Fatalf("the announced trailer never reached the client; Trailer = %v", resp.Trailer)
	}
}
