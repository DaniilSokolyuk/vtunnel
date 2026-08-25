package vtunnel

// How a forward target is read: what gets dialled, and what name is presented
// to it. Getting either wrong sends a credential somewhere it was not meant to
// go, or nowhere at all.

import (
	"net"
	"testing"
)

// A tls:// target given as an IPv6 literal keeps its brackets exactly once. The
// portless form used to gain a second pair and stop being dialable; it now
// waits for the request's port, and JoinHostPort is what puts the brackets back.
func TestForwardTargetHandlesIPv6Literals(t *testing.T) {
	for _, tc := range []struct {
		in          string
		wantHost    string
		wantSNI     string
		wantFromReq bool
	}{
		{"tls://[::1]", "::1", "::1", true},
		{"tls://[::1]:8443", "[::1]:8443", "::1", false},
		{"[::1]:443", "[::1]:443", "::1", false},
	} {
		got, ok := parseRouteTarget(tc.in)
		if !ok || got.host != tc.wantHost || got.tlsHost != tc.wantSNI || got.portFromRequest != tc.wantFromReq {
			t.Errorf("parseRouteTarget(%q) = %+v, %v; want host %q, sni %q, portFromRequest %v",
				tc.in, got, ok, tc.wantHost, tc.wantSNI, tc.wantFromReq)
			continue
		}
		dialable := got.host
		if got.portFromRequest {
			dialable = net.JoinHostPort(got.host, "5432")
		}
		if _, _, err := net.SplitHostPort(dialable); err != nil {
			t.Errorf("parseRouteTarget(%q) produced %q, which is not dialable: %v", tc.in, dialable, err)
		}
	}
}

// A raw port forward has no request to take a port from, so tls:// still means
// 443 there and nowhere else.
func TestPipeTargetDefaultsTLSTo443(t *testing.T) {
	for _, tc := range []struct{ in, wantTarget, wantSNI string }{
		{"tls://[::1]", "[::1]:443", "::1"},
		{"tls://api.corp", "api.corp:443", "api.corp"},
		{"tls://api.corp:8443", "api.corp:8443", "api.corp"},
	} {
		target, sni, ok := parsePipeTarget(tc.in)
		if !ok || target != tc.wantTarget || sni != tc.wantSNI {
			t.Errorf("parsePipeTarget(%q) = %q, %q, %v; want %q, %q, true",
				tc.in, target, sni, ok, tc.wantTarget, tc.wantSNI)
		}
	}
}

// A scheme with nothing after it is not a target.
//
// "tls://" used to come back as ":443" with no server name: a dialable address
// in Go, meaning this machine, on a route that then read as cleartext because
// there was no name to hand a handshake. A credential configured for that route
// would have gone to local port 443 in the clear. Found by
// FuzzForwardTargetIsCoherent.
func TestForwardTargetRefusesASchemeWithNoHost(t *testing.T) {
	for _, in := range []string{
		"tls://", "h2c://", "http://", // a scheme and nothing else
		"tls://:0", ":443", // a port and no host: this machine
		"tls://]0",       // a stray bracket, so the constructed address is undialable
		"tls://tls://",   // a second scheme left in the dial address
		"h2c://http://x", // and across schemes
	} {
		if got, ok := parseRouteTarget(in); ok {
			t.Errorf("parseRouteTarget(%q) = %+v; want a refusal", in, got)
		}
	}
}

// And the route that would have carried it is refused where it is declared,
// rather than found later as a connection to somewhere nobody named.
func TestForwardToRefusesASchemeWithNoHost(t *testing.T) {
	p := NewMITMProxy(WithMitmCA(testCA(t, "regression CA")))
	for _, in := range []string{"tls://", "h2c://", "http://", "tls://:0", ":443"} {
		if err := p.ForwardTo("api.corp", in, WithHeader("Authorization", "Bearer s3cret")); err == nil {
			t.Errorf("ForwardTo(%q) was accepted", in)
		}
	}
}
