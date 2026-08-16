package vtunnel_test

// The plain (non-CONNECT) forward path of the proxy must preserve HTTP
// response trailers. gRPC delivers its status (grpc-status / grpc-message)
// in trailers sent after the body, so dropping them breaks every successful
// h2c gRPC response: clients fail with "server closed the stream without
// sending trailers". Error replies survive by accident — they are
// trailers-only responses with the status in ordinary headers.
//
// Topology: h2c client → proxy (handleHTTP) → domain forward over the WS
// tunnel → HTTP/1.1 upstream that emits unannounced chunked trailers.

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/vivid-money/vtunnel"
)

func TestProxyPlainForwardPreservesGRPCTrailers(t *testing.T) {
	// Upstream stand-in for an h2c gRPC backend reached through a forward:
	// streams a body, then emits gRPC status trailers. Trailer names are not
	// known before the body is written, so they go out unannounced via
	// http.TrailerPrefix — exactly how gRPC status reaches the proxy.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		// One empty gRPC length-prefixed frame — a successful response with a body.
		if _, err := w.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
			return
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
		w.Header().Set(http.TrailerPrefix+"Grpc-Message", "")
	}))
	defer upstream.Close()

	server := vtunnel.NewServer()
	proxyPort := freePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if err := server.StartProxy(proxyAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	tunnelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		server.HandleConn(conn)
	}))
	defer tunnelServer.Close()

	client := vtunnel.NewClient(wsURL(tunnelServer))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	const domain = "grpc-backend.example.test:50051"
	upstreamHostPort := strings.TrimPrefix(upstream.URL, "http://")
	if err := client.ForwardTo(domain, upstreamHostPort); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// h2c client: cleartext HTTP/2 with prior knowledge, dialed at the proxy,
	// authority set to the forwarded domain — how gRPC tooling reaches h2c
	// upstreams through the proxy port.
	h2cTransport := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, proxyAddr)
		},
	}

	req, err := http.NewRequest(http.MethodPost,
		"http://"+domain+"/test.v1.EchoService/Echo",
		strings.NewReader("\x00\x00\x00\x00\x00"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")

	resp, err := h2cTransport.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2c RoundTrip through proxy: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body) // trailers only arrive after the body is drained
	if err != nil {
		t.Fatalf("read body through proxy: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if len(body) == 0 {
		t.Fatal("body lost through proxy")
	}
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("Grpc-Status trailer lost on the plain forward path: resp.Trailer=%v", resp.Trailer)
	}
}
