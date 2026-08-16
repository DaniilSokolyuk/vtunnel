package vtunnel

// Fuzzing the decisions this proxy makes about bytes it did not write.
//
// mitmproxy fuzzes its HTTP and SOCKS5 layers (test_http_fuzz.py,
// test_socks5_fuzz.py) because both parse attacker-chosen input. The HTTP
// parsing here is net/http's, which Go fuzzes upstream; what is ours on that
// path is everything around it — deciding what a tunnel carries, telling
// padding from payload, matching a name against the allowlist, and sweeping
// headers that must not reach the next hop. Those are the targets below, and
// each one asserts a property rather than an expected output, because the
// interesting inputs are the ones nobody would think to write down.

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/net/http/httpguts"
)

// chunkedReader hands out the input in the pieces it was given, so a test can
// ask what happens when TCP splits a message somewhere awkward.
type chunkedReader struct{ chunks [][]byte }

func (r *chunkedReader) Read(p []byte) (int, error) {
	for len(r.chunks) > 0 && len(r.chunks[0]) == 0 {
		r.chunks = r.chunks[1:]
	}
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0])
	r.chunks[0] = r.chunks[0][n:]
	return n, nil
}

func classify(chunks ...[]byte) tunnelKind {
	return classifyTunnel(bufio.NewReaderSize(&chunkedReader{chunks: chunks}, maxRequestLinePeek))
}

// What a tunnel carries must not depend on how TCP happened to deliver it.
//
// This is the property the split-request-line bug broke: the same client
// sending the same bytes was intercepted on one connection and piped on the
// next, according to where a segment boundary fell — and the sandbox router's
// tunnel hop re-segments everything it carries, so the boundary is not even the
// client's to control.
func FuzzTunnelClassificationIgnoresSegmentation(f *testing.F) {
	f.Add([]byte("GET /hello HTTP/1.1\r\nHost: api.corp\r\n\r\n"), 4)
	f.Add([]byte("GET /hello HTTP/1.1\nHost: api.corp\n\n"), 7)
	f.Add([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), 5)
	f.Add([]byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01}, 1)
	f.Add([]byte("GET mykey\r\n"), 3)
	f.Add([]byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}, 2)
	f.Add([]byte("\r\n\r\nGET / HTTP/1.1\r\n\r\n"), 2)

	f.Fuzz(func(t *testing.T, input []byte, at int) {
		if len(input) > maxRequestLinePeek {
			input = input[:maxRequestLinePeek]
		}
		whole := classify(input)

		if len(input) > 0 {
			split := ((at%len(input))+len(input))%len(input) + 1
			if split > len(input) {
				split = len(input)
			}
			if got := classify(input[:split], input[split:]); got != whole {
				t.Fatalf("split after %d byte(s) of %q changed the verdict: %v vs %v",
					split, input, got, whole)
			}
		}

		// And the verdict has to be justified by the bytes.
		switch whole {
		case tunnelTLS:
			if !startsLikeTLSRecord(input) {
				t.Fatalf("called %q TLS", input)
			}
		case tunnelH2C:
			if !bytes.HasPrefix(input, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) {
				t.Fatalf("called %q h2c", input)
			}
		case tunnelHTTP1:
			line, ok := firstLine(input)
			if !ok || !bytes.Contains(line, []byte(" HTTP/1.")) {
				t.Fatalf("called %q an HTTP/1 request", input)
			}
		}
	})
}

// The padding discard sits in front of a byte pipe, so anything it consumes
// that was not padding is silently missing from the payload.
func FuzzConnectPaddingOnlyEatsPadding(f *testing.F) {
	f.Add([]byte("\r\n\r\n\x16\x03\x01\x00\x05"))
	f.Add([]byte("\r\n\x01\x02BINARY"))
	f.Add([]byte("\r\n"))
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, input []byte) {
		br := bufio.NewReaderSize(bytes.NewReader(input), maxRequestLinePeek)
		if len(input) > 0 {
			br.Peek(1) // the caller always fills first
		}
		discardConnectPadding(br)

		remaining, _ := io.ReadAll(br)
		if len(remaining) > len(input) {
			t.Fatalf("gained bytes: %d from %d", len(remaining), len(input))
		}
		eaten := input[:len(input)-len(remaining)]
		if !bytes.Equal(input[len(eaten):], remaining) {
			t.Fatalf("what is left is not a suffix of what came in: %q from %q", remaining, input)
		}
		if len(eaten)%2 != 0 {
			t.Fatalf("ate %d bytes, which cannot be whole CRLF pairs", len(eaten))
		}
		for i := 0; i < len(eaten); i += 2 {
			if eaten[i] != '\r' || eaten[i+1] != '\n' {
				t.Fatalf("ate %q, which is not padding", eaten)
			}
		}
		if len(eaten) > 2*maxConnectPadding {
			t.Fatalf("ate %d bytes, past the %d-pair bound", len(eaten), maxConnectPadding)
		}
	})
}

// The allowlist is the sandbox's boundary, and it is matched against a name the
// sandbox chose. A miss on the router is egress, so the properties that matter
// are about what must never match.
func FuzzDomainMatchingHoldsItsBoundaries(f *testing.F) {
	patterns := map[string]int{
		"api.corp:443":     1,
		"*.wild.corp:443":  2,
		"pre.*:443":        3,
		"тест.example:443": 4,
	}

	f.Add("api.corp:443")
	f.Add("API.CORP.:0443")
	f.Add("xn--e1aybc.example:443")
	f.Add("evil.com:443")
	f.Add(":443")
	f.Add("api.corp:80")

	f.Fuzz(func(t *testing.T, authority string) {
		key, matched := bestDomainMatch(patterns, authority)
		if !matched {
			return
		}
		if _, ok := patterns[key]; !ok {
			t.Fatalf("matched %q to %q, which is not a pattern", authority, key)
		}

		host, port, err := net.SplitHostPort(authority)
		if err != nil {
			// Only the exact-key fast path can match something SplitHostPort
			// rejects, and only by being that key verbatim.
			if key != authority {
				t.Fatalf("matched unparseable %q to %q", authority, key)
			}
			return
		}
		if canonicalHost(host) == "" {
			t.Fatalf("matched %q, whose host is empty: in Go that dials the local machine", authority)
		}

		// A route is a host and a port together. Matching across ports would
		// hand out ssh on a rule written for a database.
		_, keyPort, err := net.SplitHostPort(key)
		if err != nil {
			t.Fatalf("pattern %q is not host:port", key)
		}
		if canonicalPort(keyPort) != canonicalPort(port) {
			t.Fatalf("matched %q (port %q) to %q (port %q)", authority, port, key, keyPort)
		}
	})
}

// Canonicalisation is what makes the two sides of the tunnel agree about a
// name, so it has to be stable and total.
func FuzzCanonicalHostPortIsStable(f *testing.F) {
	f.Add("API.Corp.:0443")
	f.Add("тест.example:443")
	f.Add("[::1]:443")
	f.Add(":443")
	f.Add("host:http")

	f.Fuzz(func(t *testing.T, authority string) {
		once, ok := canonicalHostPort(authority)
		if !ok {
			return
		}
		twice, ok := canonicalHostPort(once)
		if !ok {
			t.Fatalf("canonical form %q of %q is not itself canonicalisable", once, authority)
		}
		if once != twice {
			t.Fatalf("not stable: %q -> %q -> %q", authority, once, twice)
		}
		host, _, err := net.SplitHostPort(once)
		if err != nil {
			t.Fatalf("canonical form %q is not host:port: %v", once, err)
		}
		if host == "" {
			t.Fatalf("canonical form %q has no host", once)
		}
	})
}

// A hop-by-hop header that survives the sweep is one this hop forwards to the
// next, which is the whole reason the sweep exists.
func FuzzHopByHopSweepLeavesNothingBehind(f *testing.F) {
	f.Add("Connection: keep-alive, X-Secret\r\nX-Secret: 1\r\nTE: trailers\r\n", true)
	f.Add("Connection: close\r\nProxy-Authorization: Basic x\r\n", false)
	f.Add("Connection: a\r\nConnection: b\r\nA: 1\r\nB: 2\r\n", true)
	f.Add("TE: trailers, deflate\r\n", true)

	f.Fuzz(func(t *testing.T, block string, isRequest bool) {
		parsed, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
			"GET / HTTP/1.1\r\nHost: x\r\n" + block + "\r\n")))
		if err != nil {
			return
		}
		named := map[string]bool{}
		for _, value := range parsed.Header.Values("Connection") {
			for token := range strings.SplitSeq(value, ",") {
				if token = strings.TrimSpace(token); token != "" {
					named[http.CanonicalHeaderKey(token)] = true
				}
			}
		}

		removeHopByHop(parsed.Header, isRequest)

		for key := range named {
			if _, still := parsed.Header[key]; still {
				t.Fatalf("%q was named in Connection and survived the sweep", key)
			}
		}
		for _, key := range hopByHopHeaders {
			if _, still := parsed.Header[key]; still {
				t.Fatalf("hop-by-hop %q survived the sweep", key)
			}
		}
		// TE is the one exception, and only for the one token that is not
		// about this hop at all.
		if te := parsed.Header.Values("Te"); len(te) > 0 {
			if !isRequest || len(te) != 1 || te[0] != "trailers" {
				t.Fatalf("TE survived as %v (request=%v)", te, isRequest)
			}
		}
	})
}

// Injected cookies are written onto the wire, so the merged line has to stay a
// single well-formed header value, and must not lose what the client sent.
func FuzzCookieMergeKeepsEveryPair(f *testing.F) {
	f.Add("app=own", "sess=abc")
	f.Add("", "a=1")
	f.Add("a=1; b=2", "c=3")
	f.Add(";;;", "x=1")

	f.Fuzz(func(t *testing.T, existing, injected string) {
		merged := mergeCookies([]string{existing}, []string{injected})
		if strings.ContainsAny(merged, "\r\n") {
			t.Fatalf("merged value %q contains a line ending", merged)
		}
		for _, source := range []string{existing, injected} {
			for pair := range strings.SplitSeq(source, ";") {
				if pair = strings.TrimSpace(pair); pair != "" && !strings.Contains(merged, pair) {
					t.Fatalf("merged %q lost %q", merged, pair)
				}
			}
		}
	})
}

// The two sides of the tunnel must agree about what is allowlisted.
//
// They keep separate tables — the router's, filled from the domain list the
// client publishes, and the proxy's, filled by ForwardTo — and they must reach
// the same verdict for every name, because disagreeing is not a draw. If the
// router says routed and the proxy says not, the request crosses the tunnel to
// be refused with a 403 that no retry will fix. If the router says not and the
// proxy says routed, the router dials the name itself and the connection leaves
// the sandbox: no tunnel, no interception, no credential. That second one is
// the whole allowlist failing open, and it is what a single unnormalised
// spelling used to cause.
func FuzzBothSidesAgreeOnWhatIsRouted(f *testing.F) {
	f.Add("api.corp", "api.corp:443")
	f.Add("api.corp", "API.CORP.:443")
	f.Add("*.wild.corp", "svc.wild.corp:0443")
	f.Add("тест.example", "xn--e1aybc.example:443")
	f.Add("db.corp:5432", "db.corp:5432")
	f.Add("api.corp", ":443")

	f.Fuzz(func(t *testing.T, domain, authority string) {
		p := NewMITMProxy()
		if err := p.ForwardTo(domain, "127.0.0.1:9"); err != nil {
			t.Skipf("not a route: %v", err)
		}

		r := newRouter()
		// The list the client publishes is exactly what Routes() returns, so
		// the router is filled the way it is in production.
		r.SetRoutes(7, p.Routes())

		_, viaProxy := p.resolveDomain(authority)
		_, viaRouter := r.route(authority)

		if viaProxy != viaRouter {
			side := "the router would dial it out of the sandbox itself"
			if viaRouter {
				side = "the controlplane would refuse it after it crossed the tunnel"
			}
			t.Fatalf("route %q, authority %q: proxy says routed=%v, router says routed=%v — %s\n"+
				"published list: %v", domain, authority, viaProxy, viaRouter, side, p.Routes())
		}
	})
}

// A route has to match the name it was declared with. Registration and matching
// normalise separately, so an asymmetry between them produces a route that
// exists, is published to the sandbox, and answers to nothing.
func FuzzARouteMatchesItsOwnName(f *testing.F) {
	f.Add("api.corp")
	f.Add("API.CORP.")
	f.Add("тест.example")
	f.Add("db.corp:5432")
	f.Add("*.wild.corp")

	f.Fuzz(func(t *testing.T, domain string) {
		p := NewMITMProxy()
		if err := p.ForwardTo(domain, "127.0.0.1:9"); err != nil {
			t.Skipf("not a route: %v", err)
		}
		for _, key := range p.Routes() {
			if _, ok := p.resolveDomain(key); !ok {
				t.Fatalf("ForwardTo(%q) published %q, which resolves to no route",
					domain, key)
			}
		}
	})
}

// hostFromAuthority feeds the check that stops a sandbox aiming an injected
// credential at another virtual host, so it has to be stable: the host it reads
// out of an authority must be the host it reads back out of that same host.
func FuzzHostFromAuthorityIsStable(f *testing.F) {
	f.Add("api.corp:443")
	f.Add("[::1]:443")
	f.Add("[::1]")
	f.Add("api.corp")
	f.Add(":443")

	f.Fuzz(func(t *testing.T, authority string) {
		host := hostFromAuthority(authority)
		if host == "" {
			return
		}
		if again := hostFromAuthority(net.JoinHostPort(host, "443")); again != host {
			t.Fatalf("hostFromAuthority(%q) = %q, but reading that back gives %q",
				authority, host, again)
		}
	})
}

// A configured header is written onto the wire by this proxy on the sandbox's
// behalf. Whatever it contains, it must not become more than one header — a
// value that smuggles a line ending would let a route's configuration write
// requests of its own.
func FuzzHeaderInjectionCannotForgeALine(f *testing.F) {
	f.Add("Authorization", "Bearer token")
	f.Add("Authorization", "Bearer\r\nX-Smuggled: 1")
	f.Add("Cookie", "a=1")
	f.Add("X-Thing", "value\nX-Other: 2")
	f.Add("Host", "vhost.internal")

	f.Fuzz(func(t *testing.T, name, value string) {
		if !httpguts.ValidHeaderFieldName(name) {
			t.Skip("not a header name")
		}

		r, err := http.NewRequest(http.MethodGet, "http://api.corp/", nil)
		if err != nil {
			t.Skip()
		}
		injectConfiguredHeaders(r, http.Header{name: []string{value}})

		var wire bytes.Buffer
		if err := r.Write(&wire); err != nil {
			// net/http refusing to serialise a bad value is a fine outcome:
			// the request fails loudly instead of carrying a forged line.
			return
		}

		head, _, _ := strings.Cut(wire.String(), "\r\n\r\n")
		for line := range strings.SplitSeq(head, "\r\n") {
			if line == "" || strings.HasPrefix(line, "GET ") {
				continue
			}
			if !strings.Contains(line, ":") {
				t.Fatalf("injecting %q: %q produced a header line with no colon:\n%s",
					name, value, wire.String())
			}
		}
	})
}

// The forward target decides where a credential is sent and whether TLS is used
// on the way. Whatever string it is given, the answer has to be coherent.
func FuzzForwardTargetIsCoherent(f *testing.F) {
	f.Add("gw.internal:8443")
	f.Add("tls://gw.internal")
	f.Add("http://gw.internal:80")
	f.Add("tls://127.0.0.1:443")
	f.Add("")

	f.Fuzz(func(t *testing.T, addr string) {
		target, tlsHost, isTLS := parseForwardTarget(addr)

		if (tlsHost != "") != isTLS {
			t.Fatalf("parseForwardTarget(%q) = %q, %q, %v: a server name without TLS, "+
				"or TLS without a server name", addr, target, tlsHost, isTLS)
		}
		if strings.HasPrefix(target, "tls://") || strings.HasPrefix(target, "http://") {
			t.Fatalf("parseForwardTarget(%q) left a scheme on the dial address %q", addr, target)
		}
		if isTLS {
			// A TLS target is dialled, so it must carry a port for the dial and
			// a name for the handshake.
			if _, _, err := net.SplitHostPort(target); err != nil {
				t.Fatalf("parseForwardTarget(%q) says TLS but %q is not host:port", addr, target)
			}
		}
	})
}
