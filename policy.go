package vtunnel

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// Egress policy: what the sandbox may reach on its own.
//
// The egress proxy has always held one list — the domains that chain to the
// controlplane — and read everything else as "dial it". That is the right
// default for a proxy whose job is routing, and the wrong one for a sandbox
// somebody has been promised is contained. A [Policy] is how the second case is
// said out loud, and it is opt-in: an egress proxy that was never given one behaves
// exactly as it did before.
//
// What it can decide about is the traffic that comes through the proxy, which
// is all a forward proxy can see. A process that ignores HTTPS_PROXY and opens
// its own socket is not covered and cannot be — that needs a packet filter, and
// a packet filter needs a host.

// Action is what becomes of a destination no rule names.
type Action int

const (
	// ActionAllow dials it from the sandbox. It is the zero value, so a policy
	// that lists only what to refuse still lets everything else out, and a
	// egress proxy with no policy at all keeps the behaviour it has always had.
	ActionAllow Action = iota

	// ActionDeny refuses it. This is the deny-all backdrop an allowlist is
	// written against.
	ActionDeny
)

func (a Action) String() string {
	if a == ActionDeny {
		return "deny"
	}
	return "allow"
}

// Policy is the sandbox's egress rules: a default, and the exceptions to it.
//
// A rule is a CIDR, an address, a hostname or a wildcard hostname, each
// optionally followed by a port. Without a port it covers every port.
//
//	"10.0.0.0/8"      "192.0.2.7"      "2001:db8::/32"      "[::1]:5432"
//	"api.corp"        "*.corp"         "api.corp:443"       "*.corp:443"
//
// Names and addresses are matched at different moments, and the difference is
// the whole design. A name is matched before anything is resolved; an address
// rule is matched against what the name resolved to, and the connection is then
// made to that address rather than to the name a second time. So a rule about
// an address is a rule about where the bytes actually go, which is what makes
// "deny 169.254.0.0/16" hold even against a hostname that points there.
//
// Precedence, in order:
//
//   - A domain routed through the tunnel is not egress from the sandbox at all
//     — the controlplane dials it — so a route outranks every rule here.
//   - A name matching a Deny rule is refused, before resolution.
//   - Otherwise each resolved address is judged on its own: an address Deny
//     drops it, an address Allow keeps it, and anything unnamed by either is
//     kept only if the name matched an Allow or Default is [ActionAllow]. If
//     nothing survives, the connection is refused.
//
// Between two rules of the same kind the more specific wins: an exact name or a
// single address beats a wildcard or a prefix, a longer suffix or prefix beats
// a shorter one, and a rule naming a port beats one that does not. Where they
// are equally specific, Deny wins.
//
// # Writing a deny-all
//
// Put it in Default, not in Deny:
//
//	Policy{Default: ActionDeny, Allow: []string{"*.example.com"}}
//
// A literal Deny entry of "0.0.0.0/0" is accepted and is not the same thing: it
// is an explicit address deny, so it outranks an allowed name, and the policy
// above would then refuse everything. That asymmetry is deliberate — it is what
// lets an allowlist of names coexist with a deny of the cloud metadata range,
// which is the pairing that actually matters.
type Policy struct {
	// Default decides a destination no rule names.
	Default Action

	// Allow and Deny are the exceptions, in the syntax above. An entry that is
	// neither an address, a network nor a hostname is an error, reported when
	// the policy is installed rather than ignored at the moment it would have
	// mattered.
	Allow []string
	Deny  []string
}

// verdict is what the rules had to say about one destination.
type verdict int

const (
	verdictUnmatched verdict = iota // no rule named it; the default decides
	verdictAllow
	verdictDeny
)

func (v verdict) String() string {
	switch v {
	case verdictAllow:
		return "allow"
	case verdictDeny:
		return "deny"
	default:
		return "unmatched"
	}
}

// nameKind orders the three ways a rule can name a host. Exact beats a
// leftmost wildcard beats a rightmost one, which is the order routes already
// resolve in — see bestDomainMatch.
type nameKind int

const (
	nameRightmost nameKind = iota // "prefix.*"
	nameLeftmost                  // "*.suffix"
	nameExact
)

// nameRule is a rule written as a hostname.
type nameRule struct {
	host string // canonical, wildcard included
	port string // "" matches every port
	kind nameKind
	deny bool
}

// addrRule is a rule written as an address or a network.
type addrRule struct {
	prefix netip.Prefix
	port   string // "" matches every port
	deny   bool
}

// compiledPolicy is a [Policy] with its rules parsed once, so that deciding about
// a connection is a walk over ready-made values rather than a re-parse per
// dial.
type compiledPolicy struct {
	def   Action
	names []nameRule
	addrs []addrRule

	// addrAllow records that some rule permits an address outright. It is what
	// says whether a name nothing matched is worth resolving: under a deny
	// default with nothing that could permit an address either, the answer is
	// already no, and asking a resolver would be a packet sent on behalf of a
	// connection that is not going to happen.
	addrAllow bool

	// fingerprint identifies a policy by what it says rather than by which call
	// produced it, so that re-sending the same rules is recognised as the no-op
	// it is. A reconnect replays the policy, and a sandbox on a flapping link
	// replays it over and over; without this, each replay would drop the whole
	// cleartext connection pool.
	fingerprint string
}

// compile parses every rule, or fails.
//
// It fails wholesale rather than dropping what it could not read. Half a policy
// is the worst of the three outcomes available: a dropped Allow breaks traffic
// visibly, but a dropped Deny opens a hole that nothing reports, and the two are
// indistinguishable from the outside. Refusing is how a typo is a typo.
func (p Policy) compile() (*compiledPolicy, error) {
	e := &compiledPolicy{def: p.Default}
	if err := e.add(p.Allow, false); err != nil {
		return nil, err
	}
	if err := e.add(p.Deny, true); err != nil {
		return nil, err
	}
	for _, rule := range e.addrs {
		if !rule.deny {
			e.addrAllow = true
			break
		}
	}
	e.fingerprint = fingerprint(e)
	return e, nil
}

// fingerprint renders a compiled policy as the one string that stands for what
// it permits. It is built from the parsed rules rather than from the strings
// the caller wrote, so that two spellings of the same policy — `API.CORP` and
// `api.corp`, a reordered list — are recognised as the same policy and do not
// cost a pool drop apiece.
func fingerprint(e *compiledPolicy) string {
	parts := make([]string, 0, len(e.names)+len(e.addrs)+1)
	parts = append(parts, e.def.String())
	for _, rule := range e.names {
		parts = append(parts, fmt.Sprintf("n/%v/%s/%s", rule.deny, rule.host, rule.port))
	}
	for _, rule := range e.addrs {
		parts = append(parts, fmt.Sprintf("a/%v/%s/%s", rule.deny, rule.prefix, rule.port))
	}
	sort.Strings(parts[1:])
	return strings.Join(parts, " ")
}

// Validate reports whether every rule in p can be parsed. Installing a policy
// checks this too; this is for callers that would rather find out when the
// configuration is read than when it is applied.
func (p Policy) Validate() error {
	_, err := p.compile()
	return err
}

func (e *compiledPolicy) add(rules []string, deny bool) error {
	for _, raw := range rules {
		host, port, err := splitRule(raw)
		if err != nil {
			return err
		}

		if prefix, ok := parsePrefix(host); ok {
			e.addrs = append(e.addrs, addrRule{prefix: prefix, port: port, deny: deny})
			continue
		}

		canonical := canonicalHost(host)
		if canonical == "" || !isRuleHostname(canonical) {
			return fmt.Errorf("vtunnel: egress rule %q is neither an address, a network nor a hostname", raw)
		}
		e.names = append(e.names, nameRule{
			host: canonical,
			port: port,
			kind: classifyRuleHost(canonical),
			deny: deny,
		})
	}
	return nil
}

// splitRule peels an optional port off a rule.
//
// The port is optional, and so the failure of net.SplitHostPort is the ordinary
// case rather than an error: "10.0.0.0/8" has no port, and neither does the
// IPv6 address "2001:db8::1", whose colons would otherwise read as one. Only a
// bracketed host or a single trailing colon means a port was written.
func splitRule(raw string) (host, port string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("vtunnel: empty egress rule")
	}

	// An address or network that stands on its own, colons and all.
	if _, ok := parsePrefix(raw); ok {
		return raw, "", nil
	}

	h, p, splitErr := net.SplitHostPort(raw)
	if splitErr != nil {
		// No port here. An unbracketed IPv6 literal lands here too and is
		// handled above; anything else is a name.
		return raw, "", nil
	}
	if p == "" {
		return "", "", fmt.Errorf("vtunnel: egress rule %q ends in a colon but names no port", raw)
	}
	if !isPortNumber(p) {
		return "", "", fmt.Errorf("vtunnel: egress rule %q has a port that is not a number in 1..65535", raw)
	}
	return h, canonicalPort(p), nil
}

// parsePrefix reads a network or a single address, returning the network form
// of either. A bare address becomes a host route — /32 or /128 — so that one
// comparison serves both.
//
// It reports false for a zoned address rather than quietly dropping the zone. A
// zone names an interface, which is not something an egress rule is about, and
// silently widening `fe80::1%eth0` into every interface is not a reading anyone
// intended.
func parsePrefix(host string) (netip.Prefix, bool) {
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")

	if prefix, err := netip.ParsePrefix(host); err == nil {
		if prefix.Addr().Zone() != "" {
			return netip.Prefix{}, false
		}
		// Unmapped, and masked. Unmapped because ::ffff:10.0.0.1 and 10.0.0.1
		// are one host, and matchAddr unmaps what it is asked about — a rule
		// left in the mapped spelling would then never match it. The 96 is the
		// length of the mapping prefix: ::ffff:10.0.0.0/104 is 10.0.0.0/8, and
		// anything shorter than /96 reaches outside the mapped range, which no
		// IPv4 prefix can say.
		addr, bits := prefix.Addr(), prefix.Bits()
		if addr.Is4In6() {
			if bits < 96 {
				return netip.Prefix{}, false
			}
			addr, bits = addr.Unmap(), bits-96
		}
		// Masked because netip.Prefix.Contains reports false for every address
		// when the prefix carries bits below its own length, so 10.1.2.3/8 would
		// cover nothing at all rather than covering 10/8.
		return netip.PrefixFrom(addr, bits).Masked(), true
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return netip.Prefix{}, false
		}
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	return netip.Prefix{}, false
}

// isPortNumber reports whether p is a port a connection could actually be made
// to. The range matters: a rule written with a typo for a port is a rule that
// matches nothing, and saying so beats compiling it and wondering later.
func isPortNumber(p string) bool {
	if p == "" || len(p) > 5 {
		return false
	}
	n := 0
	for i := range len(p) {
		if p[i] < '0' || p[i] > '9' {
			return false
		}
		n = n*10 + int(p[i]-'0')
	}
	return n >= 1 && n <= 65535
}

// isRuleHostname reports whether s is a hostname, allowing the one wildcard
// label a rule may carry. isHostname itself refuses the "*", so the label is
// swapped out before asking.
func isRuleHostname(s string) bool {
	switch {
	case strings.HasPrefix(s, "*."):
		s = "wildcard" + s[1:]
	case strings.HasSuffix(s, ".*"):
		s = s[:len(s)-1] + "wildcard"
	}
	if strings.Contains(s, "*") {
		return false // a wildcard anywhere else is not a pattern this understands
	}
	return isHostname(s)
}

func classifyRuleHost(host string) nameKind {
	switch {
	case strings.HasPrefix(host, "*."):
		return nameLeftmost
	case strings.HasSuffix(host, ".*"):
		return nameRightmost
	default:
		return nameExact
	}
}

// matchName judges a destination by the name it was asked for, before anything
// is resolved.
func (e *compiledPolicy) matchName(host, port string) verdict {
	host = canonicalHost(host)
	if host == "" {
		return verdictUnmatched
	}
	port = canonicalPort(port)

	var best *nameRule
	for i := range e.names {
		rule := &e.names[i]
		if !rule.matches(host, port) {
			continue
		}
		if best == nil || rule.beats(*best) {
			best = rule
		}
	}
	return verdictOf(best == nil, best != nil && best.deny)
}

func (r nameRule) matches(host, port string) bool {
	if r.port != "" && r.port != port {
		return false
	}
	if r.kind == nameExact {
		return r.host == host
	}
	_, ok := wildcardHostMatches(r.host, host)
	return ok
}

// beats reports whether r is the more specific of the two, and on a tie whether
// it is the one that refuses. Deny winning a tie is the ordinary firewall rule:
// where the configuration says two things about the same destination, the safe
// reading is the one that is easy to notice and easy to correct.
func (r nameRule) beats(other nameRule) bool {
	switch {
	case r.kind != other.kind:
		return r.kind > other.kind
	case len(r.host) != len(other.host):
		return len(r.host) > len(other.host)
	case (r.port != "") != (other.port != ""):
		return r.port != ""
	default:
		return r.deny && !other.deny
	}
}

// matchAddr judges one address a name resolved to, or one the client named
// outright.
func (e *compiledPolicy) matchAddr(addr netip.Addr, port string) verdict {
	// A resolver hands back IPv4 as a 4-in-6 address as readily as not, and a
	// rule written as 10.0.0.0/8 must cover both spellings of the same host.
	addr = addr.Unmap().WithZone("")
	port = canonicalPort(port)

	var best *addrRule
	for i := range e.addrs {
		rule := &e.addrs[i]
		if rule.port != "" && rule.port != port {
			continue
		}
		if !rule.prefix.Contains(addr) {
			continue
		}
		if best == nil || rule.beats(*best) {
			best = rule
		}
	}
	return verdictOf(best == nil, best != nil && best.deny)
}

func (r addrRule) beats(other addrRule) bool {
	switch {
	case r.prefix.Bits() != other.prefix.Bits():
		return r.prefix.Bits() > other.prefix.Bits()
	case (r.port != "") != (other.port != ""):
		return r.port != ""
	default:
		return r.deny && !other.deny
	}
}

// errDenied marks a connection the policy refused, as against one that failed.
// The two have to be told apart all the way out to the client: an operator
// debugging "why can the sandbox not reach X" needs "blocked" and "unreachable"
// to look different, and a denial that presents as a timeout is why people turn
// egress policy off.
var errDenied = errors.New("vtunnel: refused by the egress policy")

// deniedError says which rule refused, and satisfies errors.Is(err, errDenied).
type deniedError struct{ what string }

func (e deniedError) Error() string { return errDenied.Error() + ": " + e.what }
func (e deniedError) Is(target error) bool {
	return target == errDenied
}

// needsResolve reports whether a name nothing matched is worth asking a
// resolver about.
//
// Under a deny default with no rule that could permit an address, the answer is
// already no, and resolving anyway would be three things at once: a packet sent
// on behalf of a connection that will not happen, a leak of what the sandbox
// wanted to reach, and — for an application that dials in a loop — this proxy
// turned into a resolver amplifier.
func (e *compiledPolicy) needsResolve(nameVerdict verdict) bool {
	return nameVerdict == verdictAllow || e.def == ActionAllow || e.addrAllow
}

// vet judges the address a dial is about to connect to. nameVerdict is what the
// rules made of the name that produced it, which still counts: a name the
// policy allowed passes an address nothing else has an opinion about.
//
// This is the last word, and it is deliberately the last word. It runs on the
// address the kernel is about to use, so a name that resolves to one address
// when it is checked and another when it is dialled has no gap to slip through.
func (e *compiledPolicy) vet(address string, nameVerdict verdict) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return deniedError{what: address + " is not an address and a port"}
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// Everything reaching here has already been resolved, so a name at this
		// point is not something to guess about.
		return deniedError{what: host + " is not an address"}
	}

	switch e.matchAddr(addr, port) {
	case verdictDeny:
		return deniedError{what: address + " is denied by an address rule"}
	case verdictAllow:
		return nil
	}
	if nameVerdict == verdictAllow || e.def == ActionAllow {
		return nil
	}
	return deniedError{what: address + " is not allowed by any rule, and the default is deny"}
}

func verdictOf(unmatched, deny bool) verdict {
	switch {
	case unmatched:
		return verdictUnmatched
	case deny:
		return verdictDeny
	default:
		return verdictAllow
	}
}
