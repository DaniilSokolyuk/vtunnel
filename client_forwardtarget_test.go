package vtunnel

// How a forward target is read: what gets dialled, and what name is presented
// to it. Getting either wrong sends a credential somewhere it was not meant to
// go, or nowhere at all.

import (
	"net"
	"testing"
)

// A tls:// target given as an IPv6 literal without a port used to gain a second
// pair of brackets and stop being dialable.
func TestForwardTargetHandlesIPv6Literals(t *testing.T) {
	for _, tc := range []struct{ in, wantTarget, wantSNI string }{
		{"tls://[::1]", "[::1]:443", "::1"},
		{"tls://[::1]:8443", "[::1]:8443", "::1"},
		{"[::1]:443", "[::1]:443", "::1"},
	} {
		target, sni, isTLS, _ := parseForwardTarget(tc.in)
		if target != tc.wantTarget || sni != tc.wantSNI || !isTLS {
			t.Errorf("parseForwardTarget(%q) = %q, %q, %v; want %q, %q, true",
				tc.in, target, sni, isTLS, tc.wantTarget, tc.wantSNI)
		}
		if _, _, err := net.SplitHostPort(target); err != nil {
			t.Errorf("parseForwardTarget(%q) produced %q, which is not dialable: %v", tc.in, target, err)
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
		target, sni, isTLS, h2c := parseForwardTarget(in)
		if target != "" || sni != "" || isTLS || h2c {
			t.Errorf("parseForwardTarget(%q) = %q, %q, %v, %v; want an empty target and nothing claimed",
				in, target, sni, isTLS, h2c)
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
