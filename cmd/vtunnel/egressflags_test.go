package main

// The three flags that make up an egress policy.
//
// They are parsed the same way on both ends, and the case worth guarding is the
// quiet one: no flags at all must mean no policy, not an empty one. An empty
// policy is a real instruction — "allow everything, and here are no exceptions"
// — and installing it where the operator asked for nothing would replace the
// behaviour every existing deployment has.

import (
	"flag"
	"io"
	"strings"
	"testing"

	vtunnel "github.com/vivid-money/vtunnel"
)

// parseEgress runs the flags the way a command would.
func parseEgress(t *testing.T, args ...string) (vtunnel.Policy, bool, error) {
	t.Helper()

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	o := egressFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	return o.policy()
}

func TestEgressFlagsAbsentMeansNoPolicy(t *testing.T) {
	t.Setenv("VTUNNEL_DEFAULT_EGRESS", "")

	_, ok, err := parseEgress(t)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	if ok {
		t.Fatal("no flags produced a policy; a tunnel nobody configured must keep the behaviour it had")
	}
}

func TestEgressFlagsBuildThePolicy(t *testing.T) {
	t.Setenv("VTUNNEL_DEFAULT_EGRESS", "")

	p, ok, err := parseEgress(t,
		"-default-egress", "deny",
		"-allow-out", "*.example.com",
		"-allow-out", "10.0.0.0/8",
		"-deny-out", "169.254.0.0/16",
	)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	if !ok {
		t.Fatal("flags were given but no policy came back")
	}
	if p.Default != vtunnel.ActionDeny {
		t.Errorf("Default = %v, want deny", p.Default)
	}
	if len(p.Allow) != 2 || p.Allow[0] != "*.example.com" || p.Allow[1] != "10.0.0.0/8" {
		t.Errorf("Allow = %v", p.Allow)
	}
	if len(p.Deny) != 1 || p.Deny[0] != "169.254.0.0/16" {
		t.Errorf("Deny = %v", p.Deny)
	}
}

// Only the two words, and no guessing at a third. A default nobody recognises
// would otherwise become "allow", which is the direction that fails open.
func TestEgressFlagsRejectAnUnknownDefault(t *testing.T) {
	t.Setenv("VTUNNEL_DEFAULT_EGRESS", "")

	if _, _, err := parseEgress(t, "-default-egress", "bogus"); err == nil {
		t.Fatal("-default-egress bogus was accepted")
	}
	// And the two that are recognised.
	for _, word := range []string{"allow", "deny"} {
		if _, _, err := parseEgress(t, "-default-egress", word); err != nil {
			t.Errorf("-default-egress %s: %v", word, err)
		}
	}
}

// A rule that cannot be read stops the command, rather than starting a sandbox
// whose rules are quietly one short.
func TestEgressFlagsRejectAnUnreadableRule(t *testing.T) {
	t.Setenv("VTUNNEL_DEFAULT_EGRESS", "")

	_, _, err := parseEgress(t, "-deny-out", "api corp")
	if err == nil {
		t.Fatal("an unreadable rule was accepted")
	}
	if !strings.Contains(err.Error(), "api corp") {
		t.Errorf("error = %v, want it to name the rule", err)
	}
}

// The environment configures the default too, so a sandbox can be started
// closed without changing its command line.
func TestEgressFlagsReadTheEnvironment(t *testing.T) {
	t.Setenv("VTUNNEL_DEFAULT_EGRESS", "deny")

	p, ok, err := parseEgress(t)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	if !ok || p.Default != vtunnel.ActionDeny {
		t.Fatalf("policy = %+v, ok = %v, want a deny default from the environment", p, ok)
	}
}
