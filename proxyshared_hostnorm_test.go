package vtunnel

import "testing"

// One hostname has several spellings, and the allowlist is keyed by exactly
// one of them. Every spelling that misses is egress: on the controlplane a miss
// fails closed, but on the sandbox router it is dialled directly, past the
// tunnel and past the injected credential — the same shape as the letter-case
// miss that bestDomainMatch already folds away.
//
// The spellings that matter, all of which reach the same server:
//   - a trailing dot, which is how a fully qualified name is written and what
//     `curl https://api.corp./` puts on the wire;
//   - a zero-padded port, which net.Dial accepts as the number it spells;
//   - an internationalised name, which every IDNA-aware client sends as
//     punycode however it was configured.
func TestBestDomainMatchFoldsHostSpellings(t *testing.T) {
	patterns := map[string]int{
		"api.corp:443":     1,
		"*.wild.corp:443":  2,
		"тест.example:443": 3,
	}

	matches := []struct {
		hostPort string
		want     string
	}{
		{"api.corp:443", "api.corp:443"},
		{"API.CORP:443", "api.corp:443"},
		{"api.corp.:443", "api.corp:443"},
		{"API.corp.:443", "api.corp:443"},
		{"api.corp:0443", "api.corp:443"},
		{"api.corp.:0443", "api.corp:443"},
		{"svc.wild.corp:443", "*.wild.corp:443"},
		{"svc.wild.corp.:443", "*.wild.corp:443"},
		// Configured in unicode, asked for in punycode: what a browser or curl
		// actually sends for a name a human typed.
		{"xn--e1aybc.example:443", "тест.example:443"},
		// And the other way round, for a client that does not convert.
		{"тест.example:443", "тест.example:443"},
	}
	for _, m := range matches {
		got, ok := bestDomainMatch(patterns, m.hostPort)
		if !ok {
			t.Errorf("bestDomainMatch(%q) = no match, want %q", m.hostPort, m.want)
			continue
		}
		if got != m.want {
			t.Errorf("bestDomainMatch(%q) = %q, want %q", m.hostPort, got, m.want)
		}
	}

	// Folding spellings must not fold distinct names together.
	for _, hostPort := range []string{
		"api.corp:80",       // another port is another route
		"notapi.corp:443",   // suffix of a key is not the key
		"api.corp.evil:443", // the dot is a separator, not a suffix
		"wild.corp:443",     // *.wild.corp needs a label in front
		"api..corp:443",     // an empty label is not the same name
		"xn--e1aybc.other:443",
	} {
		if got, ok := bestDomainMatch(patterns, hostPort); ok {
			t.Errorf("bestDomainMatch(%q) = %q, want no match", hostPort, got)
		}
	}
}

// The same folding applies to how a route is declared, so a route matches
// itself: a table keyed by the unicode spelling and asked in punycode has to
// answer, whichever side wrote which.
func TestBestDomainMatchFoldsPatternSpellings(t *testing.T) {
	patterns := map[string]int{
		"api.corp.:443":          1,
		"xn--e1aybc.example:443": 2,
		"*.wild.corp.:443":       3,
	}
	for _, hostPort := range []string{
		"api.corp:443",
		"тест.example:443",
		"svc.wild.corp:443",
	} {
		if _, ok := bestDomainMatch(patterns, hostPort); !ok {
			t.Errorf("bestDomainMatch(%q) = no match", hostPort)
		}
	}
}

// An empty host is not a host. Left alone it becomes a dialable ":443", which
// in Go means the local machine — so a miss would reach the proxy's own
// loopback instead of failing.
func TestBestDomainMatchRefusesAnEmptyHost(t *testing.T) {
	patterns := map[string]int{"api.corp:443": 1, "*.corp:443": 2}
	for _, hostPort := range []string{":443", ".:443", "..:443"} {
		if got, ok := bestDomainMatch(patterns, hostPort); ok {
			t.Errorf("bestDomainMatch(%q) = %q, want no match", hostPort, got)
		}
	}
}
