package vtunnel

import "testing"

// A hostname is case-insensitive (RFC 4343). Matching it exactly means a config
// or a client with one capital letter misses the allowlist — which fails closed
// on the controlplane but fails OPEN on the sandbox router, where a miss is
// egress straight out of the sandbox, past the tunnel and past injection.
func TestBestDomainMatchIsCaseInsensitive(t *testing.T) {
	patterns := map[string]int{
		"api.corp:443":    1,
		"*.wild.corp:443": 2,
	}

	for _, host := range []string{"API.CORP:443", "Api.Corp:443", "svc.WILD.corp:443"} {
		if _, ok := bestDomainMatch(patterns, host); !ok {
			t.Errorf("bestDomainMatch(%q) = no match, want a match", host)
		}
	}
}
