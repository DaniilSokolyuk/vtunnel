package vtunnel

import "testing"

// A hostname is case-insensitive (RFC 4343). Matching it exactly means a config
// or a client with one capital letter misses the allowlist — which fails closed
// on the controlplane but fails OPEN on the sandbox egress proxy, where a miss is
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

// A key without a port covers every port, which is what an egress rule without
// one has always meant. The two halves of the same allowlist now read a name the
// same way, and this is where that is decided for both.
func TestBestDomainMatchPortlessKeyCoversEveryPort(t *testing.T) {
	patterns := map[string]int{"db.corp": 1, "*.wild.corp": 2}

	for _, host := range []string{"db.corp:443", "db.corp:80", "db.corp:5432", "db.corp:22"} {
		if key, ok := bestDomainMatch(patterns, host); !ok || key != "db.corp" {
			t.Errorf("bestDomainMatch(%q) = %q, %v; want db.corp", host, key, ok)
		}
	}
	if key, ok := bestDomainMatch(patterns, "svc.wild.corp:9000"); !ok || key != "*.wild.corp" {
		t.Errorf("bestDomainMatch(svc.wild.corp:9000) = %q, %v; want *.wild.corp", key, ok)
	}
	// The apex is still not under its own wildcard.
	if key, ok := bestDomainMatch(patterns, "wild.corp:9000"); ok {
		t.Errorf("bestDomainMatch(wild.corp:9000) = %q; a wildcard must not match its apex", key)
	}
}

// A key naming a port still means that port alone. This is the guard on the
// widening: writing the port is how "only this port" is said, and it has to keep
// meaning that or a route for a database becomes a route for ssh.
func TestBestDomainMatchPortedKeyCoversOnlyThatPort(t *testing.T) {
	patterns := map[string]int{"db.corp:5432": 1}

	if key, ok := bestDomainMatch(patterns, "db.corp:5432"); !ok || key != "db.corp:5432" {
		t.Errorf("bestDomainMatch(db.corp:5432) = %q, %v; want a match", key, ok)
	}
	for _, host := range []string{"db.corp:22", "db.corp:443"} {
		if key, ok := bestDomainMatch(patterns, host); ok {
			t.Errorf("bestDomainMatch(%q) = %q; a route for :5432 handed out another port", host, key)
		}
	}
}

// The specificity ladder, which is the egress policy's: exact beats wildcard,
// leftmost beats rightmost, a longer host beats a shorter one, and only then
// does a key naming a port beat one that does not.
func TestBestDomainMatchSpecificityLadder(t *testing.T) {
	all := map[string]int{
		"db.corp:5432": 1,
		"db.corp":      2,
		"*.corp:5432":  3,
		"*.corp":       4,
		"db.*":         5,
	}

	for _, tc := range []struct {
		drop []string // keys removed before asking, to expose the next rung
		want string
	}{
		{want: "db.corp:5432"},
		{drop: []string{"db.corp:5432"}, want: "db.corp"},
		{drop: []string{"db.corp:5432", "db.corp"}, want: "*.corp:5432"},
		{drop: []string{"db.corp:5432", "db.corp", "*.corp:5432"}, want: "*.corp"},
		{drop: []string{"db.corp:5432", "db.corp", "*.corp:5432", "*.corp"}, want: "db.*"},
	} {
		patterns := map[string]int{}
		for k, v := range all {
			patterns[k] = v
		}
		for _, k := range tc.drop {
			delete(patterns, k)
		}
		if key, ok := bestDomainMatch(patterns, "db.corp:5432"); !ok || key != tc.want {
			t.Errorf("with %v dropped, bestDomainMatch(db.corp:5432) = %q, %v; want %q",
				tc.drop, key, ok, tc.want)
		}
	}
}

// Two keys the ladder cannot separate must not resolve one way on this request
// and the other way on the next: a Go map hands its keys over in a different
// order every time.
func TestBestDomainMatchIsDeterministicOnATie(t *testing.T) {
	patterns := map[string]int{"*.a.corp": 1, "*.b.corp": 2}

	first, ok := bestDomainMatch(patterns, "x.a.corp:443")
	if !ok {
		t.Fatal("bestDomainMatch(x.a.corp:443) = no match")
	}
	for range 50 {
		if got, _ := bestDomainMatch(patterns, "x.a.corp:443"); got != first {
			t.Fatalf("bestDomainMatch(x.a.corp:443) = %q then %q; the answer moved", first, got)
		}
	}
}

// An address written as a route key works the same way, brackets and all: the
// query carries them and a portless key does not.
func TestBestDomainMatchAddressKeys(t *testing.T) {
	patterns := map[string]int{"2001:db8::1": 1, "10.0.0.9": 2, "10.0.0.8:5432": 3}

	for _, tc := range []struct{ host, want string }{
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"[2001:db8::1]:5432", "2001:db8::1"},
		{"10.0.0.9:22", "10.0.0.9"},
		{"10.0.0.8:5432", "10.0.0.8:5432"},
	} {
		if key, ok := bestDomainMatch(patterns, tc.host); !ok || key != tc.want {
			t.Errorf("bestDomainMatch(%q) = %q, %v; want %q", tc.host, key, ok, tc.want)
		}
	}
	if key, ok := bestDomainMatch(patterns, "10.0.0.8:22"); ok {
		t.Errorf("bestDomainMatch(10.0.0.8:22) = %q; a key for :5432 handed out another port", key)
	}
}
