package vtunnel

// The egress policy, as the sandbox actually applies it.
//
// policy_test.go settles what a rule means; this settles what happens to a
// connection. The two are worth separating because almost every way of getting
// this wrong is a way of getting it wrong on one front end only — the rules
// were right and the door was not.

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel/internal/session"
)

// startPolicyEgress brings up an egress proxy with p installed.
func startPolicyEgress(t *testing.T, p *Policy) *EgressProxy {
	t.Helper()

	e := newEgressProxy()
	if p != nil {
		if err := e.SetPolicy(p); err != nil {
			t.Fatalf("SetPolicy: %v", err)
		}
	}
	if err := e.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(e.Close)
	return e
}

// connectStatus asks the egress proxy for a CONNECT tunnel and reports the
// status it answered with. The distinction the whole feature turns on lives
// here: 403 is the policy refusing, 502 is the destination not being reachable.
func connectStatus(t *testing.T, proxyAddr, target string) int {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial the egress proxy: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// A destination no rule names, under a deny default, is refused — and refused
// as a refusal, not as a failure to reach it.
func TestEgressPolicyDefaultDenyRefusesWhatNoRuleNames(t *testing.T) {
	backend := startRawEchoListener(t)
	e := startPolicyEgress(t, &Policy{Default: ActionDeny})

	if got := connectStatus(t, e.Addr().String(), backend); got != http.StatusForbidden {
		t.Fatalf("CONNECT %s = %d, want 403: the default is deny and nothing allows it", backend, got)
	}
}

// And an address rule that names it is what lets it through. This is the whole
// of `allowOut: ["10.0.0.0/8"]` against a deny-all backdrop.
func TestEgressPolicyAllowsAnAddressRule(t *testing.T) {
	backend := startRawEchoListener(t)
	e := startPolicyEgress(t, &Policy{Default: ActionDeny, Allow: []string{"127.0.0.0/8"}})

	if got := connectStatus(t, e.Addr().String(), backend); got != http.StatusOK {
		t.Fatalf("CONNECT %s = %d, want 200: 127.0.0.0/8 is allowed", backend, got)
	}
}

// A deny rule outranks an allow default, on the address the connection is
// actually made to.
func TestEgressPolicyDeniesAnAddressRule(t *testing.T) {
	backend := startRawEchoListener(t)
	e := startPolicyEgress(t, &Policy{Deny: []string{"127.0.0.0/8"}})

	if got := connectStatus(t, e.Addr().String(), backend); got != http.StatusForbidden {
		t.Fatalf("CONNECT %s = %d, want 403", backend, got)
	}
}

// The headline case, and the reason the address is judged rather than the name:
// a name the policy allows, resolving into a range the policy denies, is
// refused. Cloud metadata is reachable by name on every provider that has one.
func TestEgressPolicyVetsWhatTheNameResolvedTo(t *testing.T) {
	_, port, _ := net.SplitHostPort(startRawEchoListener(t))

	// Both of localhost's usual answers are denied, so the verdict does not
	// depend on how many addresses this machine gives back for it.
	e := startPolicyEgress(t, &Policy{
		Default: ActionDeny,
		Allow:   []string{"localhost"},
		Deny:    []string{"127.0.0.0/8", "::1/128"},
	})

	target := net.JoinHostPort("localhost", port)
	if got := connectStatus(t, e.Addr().String(), target); got != http.StatusForbidden {
		t.Fatalf("CONNECT %s = %d, want 403: the name is allowed but every address it "+
			"resolves to is denied", target, got)
	}
}

// Each candidate address is judged on its own, so denying one family still
// leaves the other reachable. Vetting a resolved list and then dialling the
// name again would have lost this, and resolving by hand and dialling the
// survivors in a loop would have lost Happy Eyeballs with it.
func TestEgressPolicyDialsTheAddressThatSurvives(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback here: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	e := startPolicyEgress(t, &Policy{
		Default: ActionDeny,
		Allow:   []string{"localhost"},
		Deny:    []string{"127.0.0.0/8"},
	})

	target := net.JoinHostPort("localhost", port)
	if got := connectStatus(t, e.Addr().String(), target); got != http.StatusOK {
		t.Fatalf("CONNECT %s = %d, want 200: ::1 is not denied and something is listening on it",
			target, got)
	}
}

// A destination that is going to be refused is refused without asking a
// resolver. `.invalid` never resolves, so a 502 here would be the DNS failure
// showing through — proof that the question was asked. It must not be: that
// question is a packet sent for a connection that will not happen, it says what
// the sandbox wanted to reach, and in a loop it makes this proxy an amplifier.
func TestEgressPolicyDeniesWithoutResolving(t *testing.T) {
	e := startPolicyEgress(t, &Policy{Default: ActionDeny})

	if got := connectStatus(t, e.Addr().String(), "nothing.invalid:443"); got != http.StatusForbidden {
		t.Fatalf("CONNECT nothing.invalid:443 = %d, want 403 without a lookup", got)
	}
}

// A name rule refuses before resolution too, which is the only moment a name
// can be judged at all.
func TestEgressPolicyDeniesByName(t *testing.T) {
	_, port, _ := net.SplitHostPort(startRawEchoListener(t))
	e := startPolicyEgress(t, &Policy{Deny: []string{"localhost"}})

	target := net.JoinHostPort("localhost", port)
	if got := connectStatus(t, e.Addr().String(), target); got != http.StatusForbidden {
		t.Fatalf("CONNECT %s = %d, want 403", target, got)
	}
}

// An authority that is not a host and a port cannot be matched against
// anything, and must not therefore fall through to the default. An empty host
// is a dialable address in Go, and it means this machine.
func TestEgressPolicyRefusesAnUnmatchableAuthority(t *testing.T) {
	e := startPolicyEgress(t, &Policy{Default: ActionAllow, Allow: []string{"127.0.0.0/8"}})

	if _, err := e.dialDirect(t.Context(), "tcp", ":443"); err == nil {
		t.Fatal("dialDirect(\":443\") succeeded; an empty host is this machine")
	}
}

// A proxy that was never given a policy behaves exactly as it always has. This
// is what makes the feature opt-in, and it is the one property every existing
// deployment depends on.
func TestEgressPolicyAbsentMeansOpenEgress(t *testing.T) {
	backend := startRawEchoListener(t)
	e := startPolicyEgress(t, nil)

	if got := connectStatus(t, e.Addr().String(), backend); got != http.StatusOK {
		t.Fatalf("CONNECT %s = %d, want 200 with no policy set", backend, got)
	}
}

// And removing a policy restores that, rather than leaving the last rules in
// force under a nil.
func TestEgressPolicyNilRestoresOpenEgress(t *testing.T) {
	backend := startRawEchoListener(t)
	e := startPolicyEgress(t, &Policy{Default: ActionDeny})

	if got := connectStatus(t, e.Addr().String(), backend); got != http.StatusForbidden {
		t.Fatalf("CONNECT before clearing = %d, want 403", got)
	}
	if err := e.SetPolicy(nil); err != nil {
		t.Fatalf("SetPolicy(nil): %v", err)
	}
	if got := connectStatus(t, e.Addr().String(), backend); got != http.StatusOK {
		t.Fatalf("CONNECT after clearing = %d, want 200", got)
	}
}

// A policy that cannot be read is refused, and the one already in force stays.
// Installing half a policy, or dropping to none, would both be worse than
// saying no.
func TestSetPolicyRejectsRulesItCannotRead(t *testing.T) {
	backend := startRawEchoListener(t)
	e := startPolicyEgress(t, &Policy{Default: ActionDeny})

	if err := e.SetPolicy(&Policy{Allow: []string{"api corp"}}); err == nil {
		t.Fatal("SetPolicy accepted an unreadable rule")
	}
	if got := connectStatus(t, e.Addr().String(), backend); got != http.StatusForbidden {
		t.Fatalf("CONNECT = %d, want 403: the refused policy must not have displaced the live one", got)
	}
}

// Re-sending the same rules is a no-op. The controlplane replays its policy on
// every reconnect, so without this a sandbox on a flapping link would drop its
// whole cleartext connection pool once per flap.
func TestSetPolicyIsANoOpWhenNothingChanged(t *testing.T) {
	e := newEgressProxy()
	p := &Policy{Default: ActionDeny, Allow: []string{"api.corp", "10.0.0.0/8"}}
	if err := e.SetPolicy(p); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	first := e.policy.Load()

	// The same rules, spelled differently and in another order.
	if err := e.SetPolicy(&Policy{Default: ActionDeny, Allow: []string{"10.0.0.0/8", "API.CORP."}}); err != nil {
		t.Fatalf("SetPolicy again: %v", err)
	}
	if e.policy.Load() != first {
		t.Fatal("an identical policy replaced the compiled one; every reconnect would drop the pool")
	}

	if err := e.SetPolicy(&Policy{Default: ActionDeny, Allow: []string{"api.corp"}}); err != nil {
		t.Fatalf("SetPolicy narrower: %v", err)
	}
	if e.policy.Load() == first {
		t.Fatal("a different policy did not replace the compiled one")
	}
}

// The cleartext HTTP path is served by net/http, which does its own dialling —
// so it is the path most easily left outside the policy. It must refuse what
// CONNECT refuses.
func TestEgressPolicyAppliesToCleartextHTTP(t *testing.T) {
	origin := newTestHTTPServer(t)
	e := startPolicyEgress(t, &Policy{Default: ActionDeny})

	resp := getThroughProxy(t, e.Addr().String(), "http://"+origin+"/")
	if resp != http.StatusForbidden {
		t.Fatalf("GET through the egress proxy = %d, want 403", resp)
	}
}

// A routed domain is not egress from this sandbox at all — the controlplane
// dials it — so the policy does not stand in its way. This is the rule that
// keeps a deny-all from also severing the tunnel.
func TestEgressPolicyLeavesRoutedDomainsAlone(t *testing.T) {
	backend := startRawEchoListener(t)

	// Stands in for the controlplane: answers CONNECT and dials the backend.
	chained := newEgressProxy()
	if err := chained.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("chained Start: %v", err)
	}
	defer chained.Close()

	e := startPolicyEgress(t, &Policy{Default: ActionDeny})
	e.SetRoutes(chained.Addr().(*net.TCPAddr).Port, []string{backend})

	if got := connectStatus(t, e.Addr().String(), backend); got != http.StatusOK {
		t.Fatalf("CONNECT %s = %d, want 200: a routed domain crosses the tunnel", backend, got)
	}
}

// The same for the cleartext path, which reaches the tunnel through a cloned
// transport. The clone inherits DialContext, and the address it dials is this
// sandbox's own loopback — so a policy dialler left on it would refuse the
// tunnel itself the moment the default became deny.
func TestEgressPolicyDoesNotJudgeTheChainedTransport(t *testing.T) {
	origin := newTestHTTPServer(t)

	chained := newEgressProxy()
	if err := chained.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("chained Start: %v", err)
	}
	defer chained.Close()

	e := startPolicyEgress(t, &Policy{Default: ActionDeny})
	e.SetRoutes(chained.Addr().(*net.TCPAddr).Port, []string{origin})

	if got := getThroughProxy(t, e.Addr().String(), "http://"+origin+"/"); got != http.StatusOK {
		t.Fatalf("routed cleartext GET = %d, want 200: the chained transport must not be judged", got)
	}
}

// socks5Reply performs the SOCKS5 handshake by hand and returns the reply code
// for one CONNECT, so a refusal can be checked as the byte the protocol has for
// it rather than as "something went wrong".
func socks5Reply(t *testing.T, proxyAddr, host string, port uint16) byte {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial the egress proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// VER, one method, no authentication.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	var chosen [2]byte
	if _, err := io.ReadFull(conn, chosen[:]); err != nil {
		t.Fatalf("read method selection: %v", err)
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return reply[1]
}

// A name the policy denies is refused with the code SOCKS5 has for exactly
// that. ReplyCode would have guessed "host unreachable" from the error text,
// which tells the client the wrong thing about a decision rather than a failure.
func TestEgressPolicySocks5DeniedNameIsNotAllowed(t *testing.T) {
	_, portStr, _ := net.SplitHostPort(startRawEchoListener(t))
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	e := startPolicyEgress(t, &Policy{Default: ActionDeny})

	const repNotAllowed = 0x02
	if got := socks5Reply(t, e.Addr().String(), "localhost", port); got != repNotAllowed {
		t.Fatalf("SOCKS5 reply = %#x, want %#x (connection not allowed by ruleset)", got, repNotAllowed)
	}
}

// An address literal is refused out of hand when there is no policy, because
// routes are written in names and a name is the only thing they can be matched
// against. A policy retires that rule instead of adding to it: addresses become
// first-class, and a CIDR allow is what makes the literal reachable — the same
// answer CONNECT has always given it.
func TestEgressPolicySocks5LiteralFollowsTheAddressRules(t *testing.T) {
	backend := startRawEchoListener(t)
	host, portStr, _ := net.SplitHostPort(backend)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	const (
		repSuccess    = 0x00
		repNotAllowed = 0x02
	)

	// No policy: the old rule stands, and the literal is refused.
	bare := startPolicyEgress(t, nil)
	if got := socks5Reply(t, bare.Addr().String(), host, port); got != repNotAllowed {
		t.Fatalf("without a policy, SOCKS5 to %s = %#x, want %#x", backend, got, repNotAllowed)
	}

	// With one that allows the range, it is reachable.
	allowed := startPolicyEgress(t, &Policy{Default: ActionDeny, Allow: []string{"127.0.0.0/8"}})
	if got := socks5Reply(t, allowed.Addr().String(), host, port); got != repSuccess {
		t.Fatalf("with 127.0.0.0/8 allowed, SOCKS5 to %s = %#x, want %#x", backend, got, repSuccess)
	}

	// And with one that denies it, refused — by the rules this time, not by the
	// blanket refusal.
	denied := startPolicyEgress(t, &Policy{Deny: []string{"127.0.0.0/8"}})
	if got := socks5Reply(t, denied.Addr().String(), host, port); got != repNotAllowed {
		t.Fatalf("with 127.0.0.0/8 denied, SOCKS5 to %s = %#x, want %#x", backend, got, repNotAllowed)
	}
}

// Whichever door a destination arrives at, it gets the same answer. Every way
// of getting this feature wrong is a way of getting it wrong on one front end
// only, so the front ends are compared against each other rather than each
// against a hand-written expectation.
func TestEgressPolicyAgreesAcrossFrontEnds(t *testing.T) {
	// One origin for all three doors, and a real HTTP one so that "allowed"
	// means a 200 rather than merely "not a 403".
	backend := newTestHTTPServer(t)
	host, portStr, _ := net.SplitHostPort(backend)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	cases := []struct {
		name    string
		policy  *Policy
		allowed bool
	}{
		{"deny by default", &Policy{Default: ActionDeny}, false},
		{"allowed by CIDR", &Policy{Default: ActionDeny, Allow: []string{"127.0.0.0/8"}}, true},
		{"denied by CIDR", &Policy{Deny: []string{"127.0.0.0/8"}}, false},
		{"allowed by default", &Policy{Default: ActionAllow}, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := startPolicyEgress(t, c.policy)

			connectOK := connectStatus(t, e.Addr().String(), backend) == http.StatusOK
			httpOK := getThroughProxy(t, e.Addr().String(), "http://"+backend+"/") == http.StatusOK
			socksOK := socks5Reply(t, e.Addr().String(), host, port) == 0x00

			if connectOK != c.allowed || httpOK != c.allowed || socksOK != c.allowed {
				t.Errorf("CONNECT=%v cleartext HTTP=%v SOCKS5=%v, want %v on all three",
					connectOK, httpOK, socksOK, c.allowed)
			}
		})
	}
}

// newTestHTTPServer starts an origin that answers 200, and returns its
// authority.
func newTestHTTPServer(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// getThroughProxy makes one proxied cleartext request and reports the status.
func getThroughProxy(t *testing.T, proxyAddr, target string) int {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial the egress proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	host := strings.TrimPrefix(target, "http://")
	host, _, _ = strings.Cut(host, "/")
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target, host); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// A sandbox too old to know what a policy is drops the unknown field and
// answers the same "OK" it answers an empty request with. Read as success, that
// is a controlplane believing a sandbox is contained while it egresses freely —
// the one failure in this feature that reports nothing anywhere. The
// acknowledgement is what makes it an error instead.
func TestSendPolicyRefusesASandboxThatDoesNotUnderstandOne(t *testing.T) {
	for _, c := range []struct {
		name      string
		reply     streamReply
		wantError bool
	}{
		{"a sandbox that applied it", streamReply{OK: true, PolicyApplied: true}, false},
		{"a sandbox too old to know the message", streamReply{OK: true}, true},
		{"a sandbox that refused it", streamReply{Error: "no"}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			// A real socket pair, not net.Pipe: net.Pipe is unbuffered, and an
			// SSH handshake has both ends write their version string before
			// either reads, so the two would block on each other forever.
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()

			ready := make(chan session.Session, 1)
			go func() {
				sandboxSide, err := ln.Accept()
				if err != nil {
					close(ready)
					return
				}
				sess, err := session.Serve(session.KindSSH, sandboxSide, session.Config{})
				if err != nil {
					close(ready)
					return
				}
				ready <- sess
				serveStreams(sess, func(stream net.Conn, _ streamHeader) {
					writeFrame(stream, c.reply)
					stream.Close()
				})
			}()

			controlplaneSide, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			cliSess, err := session.Dial(session.KindSSH, controlplaneSide, session.Config{})
			if err != nil {
				t.Fatalf("dial session: %v", err)
			}
			defer cliSess.Close()
			srvSess, ok := <-ready
			if !ok {
				t.Fatal("the sandbox side failed to handshake")
			}
			defer srvSess.Close()

			client := &Client{egressPolicy: &Policy{Default: ActionDeny}}
			err = client.sendPolicy(cliSess)
			if c.wantError && err == nil {
				t.Fatal("sendPolicy = nil, want an error")
			}
			if !c.wantError && err != nil {
				t.Fatalf("sendPolicy = %v, want nil", err)
			}
		})
	}
}

// A name the policy permits, that simply does not resolve, is a failure and not
// a refusal. The two answers send an operator to different places, and the
// policy did not refuse this — DNS did. `.invalid` is reserved never to
// resolve, so the lookup is genuinely attempted and genuinely fails.
func TestEgressPolicyResolutionFailureIsNotARefusal(t *testing.T) {
	e := startPolicyEgress(t, &Policy{
		Default: ActionDeny,
		Allow:   []string{"*.invalid"},
	})

	if got := connectStatus(t, e.Addr().String(), "nothing.invalid:443"); got != http.StatusBadGateway {
		t.Fatalf("CONNECT nothing.invalid:443 = %d, want 502: the name is allowed and the "+
			"lookup failed, which is not the policy refusing", got)
	}
}

// The feature as one invariant: under a deny default, a destination no rule
// names never gets dialled. Everything else in this file is a case; this is the
// property, and it is the one a future change has to keep.
func FuzzPolicyNeverAllowsWhatItShouldDeny(f *testing.F) {
	for _, seed := range []string{
		"127.0.0.1:443", "localhost:80", "api.corp:443", "[::1]:5432",
		"", ":443", "10.0.0.1:0", "нет.example:443", "0177.0.0.1:80",
		"2130706433:80", "fe80::1%eth0:443", "a.b.c.d.e:1",
	} {
		f.Add(seed)
	}

	// Rules that name something else entirely, so nothing the fuzzer produces
	// should ever match them — bar the exact strings they name.
	policy, err := (Policy{
		Default: ActionDeny,
		Allow:   []string{"allowed.example", "192.0.2.0/24"},
	}).compile()
	if err != nil {
		f.Fatalf("compile: %v", err)
	}

	f.Fuzz(func(t *testing.T, authority string) {
		host, port, splitErr := net.SplitHostPort(authority)
		if splitErr != nil || host == "" {
			return // dialDirect refuses these before any rule is consulted
		}

		nameVerdict := policy.matchName(host, port)
		if nameVerdict == verdictAllow || policy.needsResolve(nameVerdict) {
			// It matched an allow, or it is worth resolving because an address
			// rule might permit it. Either way vet() is what decides, and it is
			// exercised below rather than here.
			if addr, err := netip.ParseAddr(host); err == nil {
				if err := policy.vet(net.JoinHostPort(addr.String(), port), nameVerdict); err == nil {
					// Permitted, so it must have been permitted by a rule that
					// actually names it rather than by the deny default.
					if nameVerdict != verdictAllow && policy.matchAddr(addr, port) != verdictAllow {
						t.Fatalf("%q was permitted under a deny default with no rule naming it", authority)
					}
				}
			}
			return
		}

		// Nothing named it and nothing could: it must be refused without a
		// lookup, which is what needsResolve reporting false means.
		if nameVerdict == verdictUnmatched && policy.def == ActionDeny && policy.addrAllow {
			t.Fatalf("needsResolve said no for %q while an address allow exists", authority)
		}
	})
}
