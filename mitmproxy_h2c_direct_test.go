package vtunnel_test

// A cleartext HTTP/2 request that arrives at the proxy directly, with no
// CONNECT in front of it.
//
// That is how gRPC talks to a proxy it was pointed at as an ordinary endpoint,
// and the proxy serves h2c on its listener precisely so it can be. What it did
// with such a request, though, was rewrite it as HTTP/1.1 and re-issue it that
// way — which deletes TE: trailers, since a proxy strips hop-by-hop headers and
// TE is one. gRPC's response trailers are how a call reports its status, and
// the request that asks for them is the one that was thrown away.
//
// A CONNECT-wrapped h2c request has always been handled properly
// (mitmproxy_h2c_connect_test.go); this is the same traffic without the wrapper.

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/vivid-money/vtunnel"
)

func TestDirectH2CKeepsTrailersAndProtocol(t *testing.T) {
	type seen struct {
		proto string
		te    string
	}
	observed := make(chan seen, 4)

	backend := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- seen{proto: r.Proto, te: r.Header.Get("Te")}
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
		fmt.Fprint(w, "pong")
	}), &http2.Server{}))
	defer backend.Close()

	proxy := vtunnel.NewMITMProxy()
	if err := proxy.ForwardTo("grpc.corp", backend.Listener.Addr().String()); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxy.Close()

	// Cleartext h2 straight at the proxy, the way a gRPC client configured with
	// a plain endpoint speaks.
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return net.Dial(network, proxy.Addr().String())
			},
		},
	}

	req, err := http.NewRequest(http.MethodPost, "http://grpc.corp/pkg.Service/Method", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Te", "trailers")
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != "pong" {
		t.Fatalf("body = %q, want pong", body)
	}

	got := <-observed
	if got.te != "trailers" {
		t.Errorf("upstream saw Te=%q, want trailers: the proxy flattened the request to "+
			"HTTP/1.1 and stripped it, which is how a gRPC call loses its status", got.te)
	}
	if got.proto != "HTTP/2.0" {
		t.Errorf("upstream saw %s, want HTTP/2.0: an h2c request should stay h2c to an "+
			"upstream that speaks it", got.proto)
	}
	if resp.Trailer.Get("Grpc-Status") != "0" {
		t.Errorf("Grpc-Status trailer = %q, want 0", resp.Trailer.Get("Grpc-Status"))
	}
}

// The HTTP/1.1 half of the same path must not change: a plain request still
// goes out as HTTP/1.1, and TE stays hop-by-hop and is dropped.
func TestDirectHTTP1RequestsAreUnchanged(t *testing.T) {
	type seen struct {
		proto string
		te    string
	}
	observed := make(chan seen, 4)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- seen{proto: r.Proto, te: r.Header.Get("Te")}
		fmt.Fprint(w, "ok")
	}))
	defer backend.Close()

	proxy := vtunnel.NewMITMProxy()
	if err := proxy.ForwardTo("plain.corp", backend.Listener.Addr().String()); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	req, _ := http.NewRequest(http.MethodGet, "http://plain.corp/", nil)
	req.Header.Set("Te", "trailers")
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	got := <-observed
	if got.proto != "HTTP/1.1" {
		t.Errorf("upstream saw %s, want HTTP/1.1", got.proto)
	}
	if got.te != "" {
		t.Errorf("upstream saw Te=%q on an HTTP/1.1 request; it is hop-by-hop and this hop "+
			"is not asking for trailers", got.te)
	}
}

// The sandbox router has the same cleartext path, and the same sweep. It cannot
// keep the request on HTTP/2 — chaining goes through net/http's proxy support,
// which is HTTP/1.1 — but TE: trailers is what the upstream reads to decide
// whether to send trailers at all, and dropping it loses a gRPC status just as
// thoroughly.
func TestRouterKeepsTrailersOnDirectH2C(t *testing.T) {
	gotTE := make(chan string, 4)
	backend := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTE <- r.Header.Get("Te")
		fmt.Fprint(w, "ok")
	}), &http2.Server{}))
	defer backend.Close()

	server := vtunnel.NewServer()
	defer server.Close()
	if err := server.StartProxy("127.0.0.1:0"); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	routerAddr := server.Router().Addr().String()

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return net.Dial(network, routerAddr)
			},
		},
	}

	req, err := http.NewRequest(http.MethodPost, "http://"+backend.Listener.Addr().String()+"/pkg.Service/Method", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Te", "trailers")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if te := <-gotTE; te != "trailers" {
		t.Fatalf("upstream saw Te=%q, want trailers", te)
	}
}
