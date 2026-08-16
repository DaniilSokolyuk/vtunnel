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
		target, sni, isTLS := parseForwardTarget(tc.in)
		if target != tc.wantTarget || sni != tc.wantSNI || !isTLS {
			t.Errorf("parseForwardTarget(%q) = %q, %q, %v; want %q, %q, true",
				tc.in, target, sni, isTLS, tc.wantTarget, tc.wantSNI)
		}
		if _, _, err := net.SplitHostPort(target); err != nil {
			t.Errorf("parseForwardTarget(%q) produced %q, which is not dialable: %v", tc.in, target, err)
		}
	}
}
