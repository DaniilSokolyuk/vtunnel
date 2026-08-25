package vtunnel

import (
	"net/netip"
	"strings"
	"testing"
)

func mustCompile(t *testing.T, p Policy) *compiledPolicy {
	t.Helper()
	e, err := p.compile()
	if err != nil {
		t.Fatalf("compile(%+v) = %v", p, err)
	}
	return e
}

// Every shape a rule may be written in has to survive parsing, because the one
// that does not is not reported at the moment it would have mattered — it is
// reported when the policy is installed, and only if this holds.
func TestPolicyParsesEveryRuleShape(t *testing.T) {
	cases := []struct {
		rule string
		host string // what the rule should be about
		port string // "" = every port
		addr bool   // an address rule rather than a name rule
	}{
		{rule: "10.0.0.0/8", host: "10.0.0.0/8", addr: true},
		{rule: "192.0.2.7", host: "192.0.2.7/32", addr: true},
		{rule: "192.0.2.7:443", host: "192.0.2.7/32", port: "443", addr: true},
		{rule: "2001:db8::/32", host: "2001:db8::/32", addr: true},
		{rule: "2001:db8::1", host: "2001:db8::1/128", addr: true},
		{rule: "[2001:db8::1]:5432", host: "2001:db8::1/128", port: "5432", addr: true},
		{rule: "[2001:db8::/32]:443", host: "2001:db8::/32", port: "443", addr: true},
		{rule: "api.corp", host: "api.corp"},
		{rule: "api.corp:443", host: "api.corp", port: "443"},
		{rule: "*.corp", host: "*.corp"},
		{rule: "*.corp:443", host: "*.corp", port: "443"},
		{rule: "prefix.*", host: "prefix.*"},
		// Spellings that reach the same place must compile to the same rule.
		{rule: "API.CORP.", host: "api.corp"},
		{rule: "api.corp:0443", host: "api.corp", port: "443"},
		{rule: "тест.example", host: "xn--e1aybc.example"},
		// A single label is a hostname, even without a dot: a sandbox reaching
		// an internal service by short name is ordinary.
		{rule: "nexus", host: "nexus"},
	}

	for _, c := range cases {
		e := mustCompile(t, Policy{Allow: []string{c.rule}})

		switch {
		case c.addr && len(e.addrs) != 1:
			t.Errorf("%q compiled to %d address rules, want 1", c.rule, len(e.addrs))
		case c.addr:
			if got := e.addrs[0].prefix.String(); got != c.host {
				t.Errorf("%q compiled to prefix %s, want %s", c.rule, got, c.host)
			}
			if e.addrs[0].port != c.port {
				t.Errorf("%q compiled to port %q, want %q", c.rule, e.addrs[0].port, c.port)
			}
		case len(e.names) != 1:
			t.Errorf("%q compiled to %d name rules, want 1", c.rule, len(e.names))
		default:
			if e.names[0].host != c.host {
				t.Errorf("%q compiled to host %q, want %q", c.rule, e.names[0].host, c.host)
			}
			if e.names[0].port != c.port {
				t.Errorf("%q compiled to port %q, want %q", c.rule, e.names[0].port, c.port)
			}
		}
	}
}

// A rule that cannot be read is refused, and the whole policy with it. Dropping
// the unreadable one and keeping the rest is the outcome to avoid: a dropped
// allow breaks traffic where somebody notices, and a dropped deny opens a hole
// where nobody does.
func TestPolicyRefusesRulesItCannotRead(t *testing.T) {
	for _, rule := range []string{
		"",
		"   ",
		"api.corp:",         // a colon and no port
		"api.corp:https",    // a service name is not a port here
		"api.corp:99999999", // still refused as a name, not silently truncated
		"*.*.corp",          // a wildcard is one label, on a border
		"api.*.corp",        // and not in the middle
		"api corp",          // a space is not a hostname character
		"-api.corp",         // a label may not start with a hyphen
		"10.0.0.0/64",       // not a v4 prefix
		"2001:db8::/200",    // not a v6 prefix either
	} {
		if err := (Policy{Allow: []string{rule}}).Validate(); err == nil {
			t.Errorf("Validate(allow %q) = nil, want an error", rule)
		}
		if err := (Policy{Deny: []string{rule}}).Validate(); err == nil {
			t.Errorf("Validate(deny %q) = nil, want an error", rule)
		}
	}
}

// The error names the rule, because the caller wrote a list and has to be told
// which line of it is wrong.
func TestPolicyErrorNamesTheOffendingRule(t *testing.T) {
	err := (Policy{Allow: []string{"10.0.0.0/8", "api corp", "*.ok"}}).Validate()
	if err == nil {
		t.Fatal("Validate = nil, want an error")
	}
	if !strings.Contains(err.Error(), "api corp") {
		t.Errorf("Validate = %v, want the message to name %q", err, "api corp")
	}
}

// A rule without a port is about the host, not about one way of reaching it.
// Reading a bare rule as ":443" would leave every other port to the default,
// which for a deny-all is an allowlist that silently covers one port.
func TestPolicyRuleWithoutAPortCoversEveryPort(t *testing.T) {
	e := mustCompile(t, Policy{Allow: []string{"api.corp", "10.0.0.0/8"}})

	for _, port := range []string{"80", "443", "5432", "1"} {
		if got := e.matchName("api.corp", port); got != verdictAllow {
			t.Errorf("matchName(api.corp, %s) = %v, want allow", port, got)
		}
		if got := e.matchAddr(netip.MustParseAddr("10.1.2.3"), port); got != verdictAllow {
			t.Errorf("matchAddr(10.1.2.3, %s) = %v, want allow", port, got)
		}
	}
}

// And a rule with one is about that port alone.
func TestPolicyRuleWithAPortCoversOnlyThatPort(t *testing.T) {
	e := mustCompile(t, Policy{Allow: []string{"api.corp:443", "10.0.0.0/8:5432"}})

	if got := e.matchName("api.corp", "443"); got != verdictAllow {
		t.Errorf("matchName(api.corp, 443) = %v, want allow", got)
	}
	if got := e.matchName("api.corp", "80"); got != verdictUnmatched {
		t.Errorf("matchName(api.corp, 80) = %v, want unmatched", got)
	}
	if got := e.matchAddr(netip.MustParseAddr("10.1.2.3"), "5432"); got != verdictAllow {
		t.Errorf("matchAddr(10.1.2.3, 5432) = %v, want allow", got)
	}
	if got := e.matchAddr(netip.MustParseAddr("10.1.2.3"), "443"); got != verdictUnmatched {
		t.Errorf("matchAddr(10.1.2.3, 443) = %v, want unmatched", got)
	}
	// A zero-padded port is the port it spells, on both sides of the comparison.
	if got := e.matchName("api.corp", "0443"); got != verdictAllow {
		t.Errorf("matchName(api.corp, 0443) = %v, want allow", got)
	}
}

// A name is matched the way a route is matched, or the allowlist is one
// keystroke wide — the same folding bestDomainMatch does, for the same reason.
func TestPolicyFoldsNameSpellings(t *testing.T) {
	e := mustCompile(t, Policy{Allow: []string{"api.corp", "тест.example", "*.wild.corp"}})

	for _, host := range []string{
		"api.corp",
		"API.CORP",
		"api.corp.",
		"API.Corp.",
		"тест.example",
		"xn--e1aybc.example",
		"svc.wild.corp",
		"svc.wild.corp.",
		"a.b.wild.corp",
	} {
		if got := e.matchName(host, "443"); got != verdictAllow {
			t.Errorf("matchName(%q) = %v, want allow", host, got)
		}
	}

	// Folding spellings must not fold distinct names together.
	for _, host := range []string{
		"notapi.corp",
		"api.corp.evil",
		"wild.corp", // *.wild.corp needs a label in front
		"xn--e1aybc.other",
		"", // no host is not every host
	} {
		if got := e.matchName(host, "443"); got != verdictUnmatched {
			t.Errorf("matchName(%q) = %v, want unmatched", host, got)
		}
	}
}

// Where two rules both match, the more specific one decides. Without this a
// deny of one host inside an allowed domain does nothing, which is the shape
// every allowlist-with-an-exception is written in.
func TestPolicyMoreSpecificNameRuleWins(t *testing.T) {
	e := mustCompile(t, Policy{
		Allow: []string{"*.corp"},
		Deny:  []string{"secret.corp", "*.internal.corp"},
	})

	cases := []struct {
		host string
		want verdict
	}{
		{"api.corp", verdictAllow},             // only the wildcard
		{"secret.corp", verdictDeny},           // exact beats wildcard
		{"db.internal.corp", verdictDeny},      // longer suffix beats shorter
		{"deep.db.internal.corp", verdictDeny}, // and keeps beating it
		{"internal.corp", verdictAllow},        // *.internal.corp needs a label
		{"notsecret.corp", verdictAllow},       // a suffix of a key is not the key
	}
	for _, c := range cases {
		if got := e.matchName(c.host, "443"); got != c.want {
			t.Errorf("matchName(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

// Exact beats a leftmost wildcard beats a rightmost one — the order routes
// already resolve in.
func TestPolicyNameRuleKindsAreOrdered(t *testing.T) {
	e := mustCompile(t, Policy{
		Allow: []string{"api.*"},
		Deny:  []string{"*.corp"},
	})
	// Both match api.corp; the leftmost wildcard is the more specific kind.
	if got := e.matchName("api.corp", "443"); got != verdictDeny {
		t.Errorf("matchName(api.corp) = %v, want deny (*.corp outranks api.*)", got)
	}

	e = mustCompile(t, Policy{
		Allow: []string{"api.corp"},
		Deny:  []string{"*.corp"},
	})
	if got := e.matchName("api.corp", "443"); got != verdictAllow {
		t.Errorf("matchName(api.corp) = %v, want allow (exact outranks *.corp)", got)
	}
}

// A rule naming a port is the more specific of two that otherwise agree.
func TestPolicyPortedRuleBeatsBareRule(t *testing.T) {
	e := mustCompile(t, Policy{
		Allow: []string{"api.corp"},
		Deny:  []string{"api.corp:22"},
	})
	if got := e.matchName("api.corp", "443"); got != verdictAllow {
		t.Errorf("matchName(api.corp, 443) = %v, want allow", got)
	}
	if got := e.matchName("api.corp", "22"); got != verdictDeny {
		t.Errorf("matchName(api.corp, 22) = %v, want deny", got)
	}
}

// Where the configuration says two equally specific things about the same
// destination, the safe reading wins. A refusal is noticed and corrected; the
// other way round is noticed by whoever finds the traffic.
func TestPolicyDenyWinsATie(t *testing.T) {
	e := mustCompile(t, Policy{
		Allow: []string{"api.corp", "10.0.0.0/8"},
		Deny:  []string{"api.corp", "10.0.0.0/8"},
	})
	if got := e.matchName("api.corp", "443"); got != verdictDeny {
		t.Errorf("matchName = %v, want deny", got)
	}
	if got := e.matchAddr(netip.MustParseAddr("10.1.2.3"), "443"); got != verdictDeny {
		t.Errorf("matchAddr = %v, want deny", got)
	}
}

// The longer prefix decides, which is what lets a deny-all be written as a
// backdrop with holes punched in it.
func TestPolicyLongerPrefixWins(t *testing.T) {
	e := mustCompile(t, Policy{
		Allow: []string{"10.0.0.0/8"},
		Deny:  []string{"10.1.0.0/16", "0.0.0.0/0"},
	})

	cases := []struct {
		addr string
		want verdict
	}{
		{"10.2.3.4", verdictAllow}, // /8 beats /0
		{"10.1.2.3", verdictDeny},  // /16 beats /8
		{"192.0.2.1", verdictDeny}, // only /0
	}
	for _, c := range cases {
		if got := e.matchAddr(netip.MustParseAddr(c.addr), "443"); got != c.want {
			t.Errorf("matchAddr(%s) = %v, want %v", c.addr, got, c.want)
		}
	}
}

// A prefix written with host bits set covers what it says it covers.
// netip.Prefix.Contains reports false for everything unless the prefix is
// masked, so an unmasked rule would silently match nothing at all.
func TestPolicyMasksPrefixesWithHostBits(t *testing.T) {
	e := mustCompile(t, Policy{Allow: []string{"10.1.2.3/8"}})
	if got := e.matchAddr(netip.MustParseAddr("10.9.9.9"), "443"); got != verdictAllow {
		t.Errorf("matchAddr(10.9.9.9) = %v, want allow", got)
	}
}

// A resolver hands back IPv4 as a 4-in-6 address as readily as not, and both
// spellings are the same host. Comparing them unmapped is what keeps a v4 rule
// from missing half the answers it was written for.
func TestPolicyMatchesFourInSixAddresses(t *testing.T) {
	e := mustCompile(t, Policy{Deny: []string{"169.254.0.0/16"}})

	for _, addr := range []string{"169.254.169.254", "::ffff:169.254.169.254"} {
		if got := e.matchAddr(netip.MustParseAddr(addr), "80"); got != verdictDeny {
			t.Errorf("matchAddr(%s) = %v, want deny", addr, got)
		}
	}
}

// A zone identifier says which interface a link-local address is on. It is not
// something a rule can be written about, and stripping it is what keeps such an
// address from slipping past one.
func TestPolicyIgnoresIPv6Zones(t *testing.T) {
	e := mustCompile(t, Policy{Deny: []string{"fe80::/10"}})
	addr := netip.MustParseAddr("fe80::1%eth0")
	if got := e.matchAddr(addr, "443"); got != verdictDeny {
		t.Errorf("matchAddr(%s) = %v, want deny", addr, got)
	}
}

// Name rules and address rules are separate stages, so a name rule says nothing
// about an address and the other way round. This is what makes the two-stage
// decision in EgressProxy.decide well defined.
func TestPolicyNameAndAddressRulesDoNotCross(t *testing.T) {
	e := mustCompile(t, Policy{Allow: []string{"api.corp"}, Deny: []string{"10.0.0.0/8"}})

	if got := e.matchAddr(netip.MustParseAddr("192.0.2.1"), "443"); got != verdictUnmatched {
		t.Errorf("matchAddr = %v, want unmatched: no address rule covers it", got)
	}
	if got := e.matchName("10.1.2.3", "443"); got != verdictUnmatched {
		t.Errorf("matchName(10.1.2.3) = %v, want unmatched: the deny is an address rule", got)
	}
}

// An empty policy names nothing, and its default decides everything.
func TestPolicyEmptyPolicyMatchesNothing(t *testing.T) {
	e := mustCompile(t, Policy{Default: ActionDeny})

	if got := e.matchName("api.corp", "443"); got != verdictUnmatched {
		t.Errorf("matchName = %v, want unmatched", got)
	}
	if got := e.matchAddr(netip.MustParseAddr("10.1.2.3"), "443"); got != verdictUnmatched {
		t.Errorf("matchAddr = %v, want unmatched", got)
	}
	if e.addrAllow {
		t.Error("addrAllow = true on an empty policy")
	}
	// Nothing could permit an address and the default refuses, so there is
	// nothing a resolver could tell us that would change the answer.
	if e.needsResolve(verdictUnmatched) {
		t.Error("needsResolve = true under a deny default with no address allow")
	}
	if e.def != ActionDeny {
		t.Errorf("def = %v, want deny", e.def)
	}
}

func TestActionString(t *testing.T) {
	if got := ActionAllow.String(); got != "allow" {
		t.Errorf("ActionAllow = %q", got)
	}
	if got := ActionDeny.String(); got != "deny" {
		t.Errorf("ActionDeny = %q", got)
	}
}

// The parser reads a string an operator wrote, and a panic in it takes the
// sandbox's proxy with it. Everything it is given must come back as a rule or
// as an error.
func FuzzPolicyRule(f *testing.F) {
	for _, seed := range []string{
		"10.0.0.0/8", "192.0.2.7:443", "[2001:db8::1]:5432", "2001:db8::/32",
		"api.corp", "*.corp:443", "prefix.*", "api.corp:", ":", "]:[", "*",
		"api.corp:0443", "тест.example", strings.Repeat("a.", 200) + "corp",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, rule string) {
		e, err := (Policy{Allow: []string{rule}}).compile()
		if err != nil {
			return
		}
		if len(e.names)+len(e.addrs) != 1 {
			t.Fatalf("rule %q compiled to %d name and %d address rules, want one in total",
				rule, len(e.names), len(e.addrs))
		}
		// A compiled rule must be usable: matching is what happens next, and it
		// runs for every connection the sandbox makes.
		e.matchName("api.corp", "443")
		e.matchAddr(netip.MustParseAddr("10.1.2.3"), "443")
		e.matchAddr(netip.MustParseAddr("2001:db8::1"), "443")
	})
}
