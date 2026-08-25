package e2e_test

// ALPN, end to end.
//
// There are two handshakes, and the proxy sits between them holding both. What
// it offers the upstream is built from what the client offered it; what it
// answers the client is built from what the upstream settled on. Neither list is
// the client's own, and the rules that turn one into the other are the whole
// subject of this file.
//
// Two facts about the negotiation itself, because every expectation below rests
// on them:
//
//   - The server picks, not the client. crypto/tls walks the *server's* list in
//     the outer loop and returns the first entry the client also offered
//     (handshake_server.go, negotiateALPN). So whoever writes NextProtos on the
//     server side writes the preference order, and a client listing h2 first
//     gets http/1.1 anyway if the server listed http/1.1 first.
//   - A server offering only "h2" to a client offering only "http/1.1" does not
//     fail the handshake. Go returns no protocol at all and lets it through, for
//     the sake of servers configured h2-only that still serve HTTP/1.1 (Go issue
//     46310). An empty NegotiatedProtocol therefore means "no agreement", not
//     "HTTP/1.1", and a server that meant it will drop the connection later.

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/http2"

	"github.com/vivid-money/vtunnel"
)

// alpnReport is what every upstream in this file answers with: the protocol it
// ended up serving, and the ALPN entry the handshake actually agreed on. The
// second is the one that matters — it is empty exactly when nobody agreed.
func alpnReport() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		negotiated := ""
		if r.TLS != nil {
			negotiated = r.TLS.NegotiatedProtocol
		}
		fmt.Fprintf(w, "proto=%s alpn=%q injected=%s", r.Proto, negotiated, r.Header.Get(injectedHeader))
	})
}

// startStrictH2Upstream offers only h2 and means it: a connection that
// negotiated anything else is dropped rather than served over HTTP/1.1. This is
// the shape Go's own httptest cannot produce — its h2 server answers HTTP/1.1
// too, which hides whether the proxy ever offered h2 at all.
func startStrictH2Upstream(t *testing.T, h http.Handler) (string, *x509.CertPool) {
	t.Helper()

	cert, pool := selfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srv := &http2.Server{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				tlsConn := conn.(*tls.Conn)
				if err := tlsConn.Handshake(); err != nil {
					conn.Close()
					return
				}
				if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
					conn.Close() // the refusal an h2-only upstream is for
					return
				}
				srv.ServeConn(conn, &http2.ServeConnOpts{Handler: h})
			}()
		}
	}()
	return "tls://" + ln.Addr().String(), pool
}

// startBothALPNUpstream advertises h2 and http/1.1, in that order, and serves
// either.
func startBothALPNUpstream(t *testing.T, h http.Handler) (string, *x509.CertPool) {
	t.Helper()

	ts := httptest.NewUnstartedServer(h)
	ts.EnableHTTP2 = true
	ts.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	ts.StartTLS()
	t.Cleanup(ts.Close)

	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	return "tls://" + ts.Listener.Addr().String(), pool
}

// startNoALPNUpstream answers the ALPN extension with nothing at all, the way a
// great many TLS servers still do. There is then no negotiated protocol for the
// proxy to mirror, and it has to decide what to tell the client on its own.
func startNoALPNUpstream(t *testing.T, h http.Handler) (string, *x509.CertPool) {
	t.Helper()

	cert, pool := selfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler: h,
		// Without this net/http installs its own h2 handler and starts
		// advertising h2 again behind our back.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "tls://" + ln.Addr().String(), pool
}

// ---------------------------------------------------------------------------

// TestALPNUpstreamOffer pins what the proxy offers the upstream, by putting
// upstreams in front of it that answer differently and reporting what they saw.
func TestALPNUpstreamOffer(t *testing.T) {
	tests := []struct {
		name     string
		start    func(*testing.T, http.Handler) (string, *x509.CertPool)
		client   clientMode
		wantALPN string // what the upstream handshake agreed on
	}{
		{
			name:     "both-alpn/h2 client gets h2",
			start:    startBothALPNUpstream,
			client:   clientModes[2], // h2 over TLS
			wantALPN: "h2",
		},
		{
			// The upstream picks, and it picks h2 — even for an HTTP/1.1 client,
			// because the offer no longer depends on what the client is doing.
			// The client's own leg stays HTTP/1.1; the two are translated.
			name:     "both-alpn/h1 client still lets the upstream choose h2",
			start:    startBothALPNUpstream,
			client:   clientModes[1], // http/1.1 over TLS
			wantALPN: "h2",
		},
		{
			// The upstream advertises nothing, so there is nothing to mirror and
			// the far leg can only be HTTP/1.1 — whatever the client is doing.
			name:     "no-alpn/h2 client still reaches it",
			start:    startNoALPNUpstream,
			client:   clientModes[2],
			wantALPN: "",
		},
		{
			name:     "no-alpn/h1 client",
			start:    startNoALPNUpstream,
			client:   clientModes[1],
			wantALPN: "",
		},
		{
			name:     "strict-h2/h2 client gets h2",
			start:    startStrictH2Upstream,
			client:   clientModes[2],
			wantALPN: "h2",
		},
		{
			// The pairing this file was written to catch. An upstream that
			// speaks only h2, reached by a client that speaks only HTTP/1.1:
			// both floor and ceiling are in the offer, so the handshake lands on
			// h2 and the proxy translates. Withholding h2 here used to fail
			// silently — Go answers such a handshake with no protocol at all
			// rather than an alert, so the connection came up and died on the
			// first request as an unexplained 502.
			name:     "strict-h2/h1 client reaches it by translation",
			start:    startStrictH2Upstream,
			client:   clientModes[1],
			wantALPN: "h2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target, roots := tc.start(t, alpnReport())

			c := newChain(t, func(p *vtunnel.MITMProxy) {
				p.SetTransportTLSConfig(&tls.Config{RootCAs: roots})
			})
			if err := c.proxy.ForwardTo(matrixHost, target, vtunnel.WithHeader(injectedHeader, injectedValue)); err != nil {
				t.Fatalf("ForwardTo: %v", err)
			}
			c.waitRoute(t, matrixHost)

			resp, err := tc.client.build(t, c).Get("https://" + matrixHost + "/alpn")
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %s, body = %s", resp.Status, body)
			}
			if want := fmt.Sprintf("alpn=%q", tc.wantALPN); !strings.Contains(string(body), want) {
				t.Errorf("upstream handshake agreed on the wrong thing: want %s, got %s", want, body)
			}
			if !strings.Contains(string(body), "injected="+injectedValue) {
				t.Errorf("injected header never reached the upstream: %s", body)
			}
		})
	}
}

// TestALPNAnsweredToTheClient pins the other handshake: what the client is
// offered, and in particular whose preference order decides it.
func TestALPNAnsweredToTheClient(t *testing.T) {
	tests := []struct {
		name      string
		start     func(*testing.T, http.Handler) (string, *x509.CertPool)
		offer     []string // the client's ALPN list, in the client's order
		wantProto string   // what the client must end up speaking
	}{
		{
			// Mirroring: the upstream is h2-capable and the client asked for h2,
			// so both legs are h2 and nothing has to be translated.
			name:      "mirrored h2",
			start:     startBothALPNUpstream,
			offer:     []string{"h2", "http/1.1"},
			wantProto: "HTTP/2.0",
		},
		{
			// The client's order is not the deciding one when there is an
			// upstream to mirror: it offered h2 first and gets http/1.1, because
			// http/1.1 is what the far side settled on.
			name:      "client asks h2 first, upstream has only http/1.1",
			start:     startTLSH1Upstream,
			offer:     []string{"h2", "http/1.1"},
			wantProto: "HTTP/1.1",
		},
		{
			// ...and when the client leaves h2 out entirely, it is not given h2
			// even though the upstream would have.
			name:      "client asks http/1.1 only against an h2 upstream",
			start:     startBothALPNUpstream,
			offer:     []string{"http/1.1"},
			wantProto: "HTTP/1.1",
		},
		{
			// The upstream said nothing, so the client's own list decides, and
			// its order with it: h2 first means h2, even though the far leg will
			// be HTTP/1.1 and every request translated across.
			name:      "no upstream ALPN, client order decides — h2 first",
			start:     startNoALPNUpstream,
			offer:     []string{"h2", "http/1.1"},
			wantProto: "HTTP/2.0",
		},
		{
			// The same upstream, the same two protocols, the other order. This
			// is the case a fixed server-side list gets wrong: crypto/tls walks
			// the server's list, so answering from {"h2","http/1.1"} would hand
			// h2 to a client that put http/1.1 first and left it no way to say
			// otherwise.
			name:      "no upstream ALPN, client order decides — http/1.1 first",
			start:     startNoALPNUpstream,
			offer:     []string{"http/1.1", "h2"},
			wantProto: "HTTP/1.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target, roots := tc.start(t, alpnReport())

			c := newChain(t, func(p *vtunnel.MITMProxy) {
				p.SetTransportTLSConfig(&tls.Config{RootCAs: roots})
			})
			if err := c.proxy.ForwardTo(matrixHost, target, vtunnel.WithHeader(injectedHeader, injectedValue)); err != nil {
				t.Fatalf("ForwardTo: %v", err)
			}
			c.waitRoute(t, matrixHost)

			// ForceAttemptHTTP2 must follow the offer rather than lead it:
			// net/http appends "h2" to NextProtos whenever it is set, so
			// setting it unconditionally would put h2 on the wire even in the
			// cases that exist to leave it off.
			client := matrixClient(t, &http.Transport{
				Proxy: c.proxyURL(),
				TLSClientConfig: &tls.Config{
					RootCAs:    c.caPool,
					NextProtos: tc.offer,
				},
				ForceAttemptHTTP2: slices.Contains(tc.offer, "h2"),
			})

			resp, err := client.Get("https://" + matrixHost + "/alpn")
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			if resp.Proto != tc.wantProto {
				t.Errorf("client leg spoke %s, want %s (upstream reported %s)", resp.Proto, tc.wantProto, body)
			}
		})
	}
}

// TestALPNClientOffersNothingUsable covers a client whose ALPN list this proxy
// cannot carry at all. The handshake is refused with no_application_protocol,
// which is the answer RFC 7301 asks for and one the client can act on — rather
// than the proxy quietly picking HTTP for a client that asked for IMAP and
// failing later, somewhere less legible.
//
// The unit test of the same rule covers a route served in process; this one
// covers a forwarded route with a live upstream behind it, where the refusal has
// to survive the pre-dial that happens mid-handshake.
func TestALPNClientOffersNothingUsable(t *testing.T) {
	target, roots := startBothALPNUpstream(t, alpnReport())

	c := newChain(t, func(p *vtunnel.MITMProxy) {
		p.SetTransportTLSConfig(&tls.Config{RootCAs: roots})
	})
	if err := c.proxy.ForwardTo(matrixHost, target); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	c.waitRoute(t, matrixHost)

	conn, err := connectThroughProxy(t.Context(), c.proxyAddr, matrixHost+":443")
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: matrixHost,
		RootCAs:    c.caPool,
		NextProtos: []string{"imap", "ftp"},
	})
	err = tlsConn.Handshake()
	if err == nil {
		t.Fatalf("handshake succeeded, negotiating %q with a client that offered only imap and ftp",
			tlsConn.ConnectionState().NegotiatedProtocol)
	}
	if !strings.Contains(err.Error(), "no application protocol") {
		t.Fatalf("refused with %v, want no_application_protocol", err)
	}
}

// selfSignedCert issues a leaf for 127.0.0.1, for upstreams built by hand rather
// than by httptest.
func selfSignedCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	ts := httptest.NewUnstartedServer(http.NotFoundHandler())
	ts.StartTLS()
	cert := ts.TLS.Certificates[0]
	leaf := ts.Certificate()
	ts.Close()

	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return cert, pool
}
