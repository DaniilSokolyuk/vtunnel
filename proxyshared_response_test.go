package vtunnel

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// An upstream may legally send Content-Length together with trailers — HTTP/2
// has no chunked encoding, so an h2 upstream forwarded to an HTTP/1.1 client
// does exactly that. Copying the length through makes net/http pick identity
// framing, which has nowhere to put a trailer: the client is told to expect one
// and never receives it.
func TestCopyResponseForwardsTrailersDespiteContentLength(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		copyResponse(w, &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Length": {"2"}},
			Body:       io.NopCloser(strings.NewReader("ok")),
			Trailer:    http.Header{"Grpc-Status": {"0"}},
		})
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want %q", body, "ok")
	}
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("Grpc-Status trailer = %q, want %q", got, "0")
	}
}

// Set replaces, so setting each value of a repeated trailer in turn keeps only
// the last one. Repeated grpc-metadata-* and X-Trace trailers are ordinary.
func TestForwardTrailersKeepsRepeatedValues(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		copyResponse(w, &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader("ok")),
			Trailer:    http.Header{"X-Meta": {"a", "b"}},
		})
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if got := resp.Trailer.Values("X-Meta"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("X-Meta trailer = %v, want [a b]", got)
	}
}

// A body that stops early must not be handed to the client as a complete
// response. Delivering a truncated artifact framed as a well-formed 200 is
// silent corruption the caller has no way to detect.
func TestCopyResponseAbortsOnTruncatedBody(t *testing.T) {
	// An upstream that opens a chunked body, sends one chunk, and hangs up
	// without the terminating one — an artifact download cut in half.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.ReadAll(io.LimitReader(conn, 1)) // wait for the request line
		conn.Write([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nshort\r\n"))
	}()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.Get("http://" + ln.Addr().String() + "/")
		if err != nil {
			t.Errorf("upstream GET: %v", err)
			return
		}
		defer resp.Body.Close()
		copyResponse(w, resp)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		// Aborting before any byte reached the client is an acceptable outcome too.
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err == nil {
		t.Fatalf("read body = %q with no error, want the truncation to surface", body)
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("read body error = %v, want something other than a clean EOF", err)
	}
}

// Connection may arrive as several header lines; Get reads only the first, so
// everything named on the later ones is forwarded to the next hop.
func TestRemoveHopByHopReadsEveryConnectionLine(t *testing.T) {
	h := http.Header{}
	h.Add("Connection", "X-First")
	h.Add("Connection", "X-Second")
	h.Set("X-First", "1")
	h.Set("X-Second", "2")

	removeHopByHop(h, false)

	if got := h.Get("X-Second"); got != "" {
		t.Fatalf("X-Second = %q after removeHopByHop, want it dropped", got)
	}
	if got := h.Get("X-First"); got != "" {
		t.Fatalf("X-First = %q after removeHopByHop, want it dropped", got)
	}
}
