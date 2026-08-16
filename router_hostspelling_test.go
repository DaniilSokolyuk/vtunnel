package vtunnel_test

// A name has more than one spelling, and only one of them is in the allowlist.
// On the sandbox router a miss is not a refusal — it is dialled directly, out
// of the sandbox, past the tunnel and past the credential the controlplane
// would have injected. So every spelling that reaches the same server has to
// reach the same route.
//
// The test shape throughout: two echo servers, one reachable only through the
// tunnel and one standing in for the open internet, with the route pointed at
// the first. Which one answers says which way the connection went.

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func routedThroughSpelling(t *testing.T, route, asked string) string {
	t.Helper()

	tunnelSide, _ := tcpEcho(t, "controlplane")
	direct, _ := tcpEcho(t, "direct")
	_, port, _ := net.SplitHostPort(direct)

	routerAddr, client := sandbox(t)
	if err := client.Proxy().ForwardTo(fmt.Sprintf("%s:%s", route, port), tunnelSide); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	conn := socksDial(t, routerAddr, fmt.Sprintf("%s:%s", asked, port))
	return ask(t, conn, "hi")
}

// `curl https://api.corp./` puts the trailing dot on the wire, and it reaches
// the same server: crypto/tls even strips it back off for SNI. The allowlist
// has to read it as the same name.
func TestTrailingDotStaysInsideTheTunnel(t *testing.T) {
	if got := routedThroughSpelling(t, "localhost", "localhost."); !strings.HasPrefix(got, "controlplane:") {
		t.Fatalf("answer = %q, want the controlplane's target: a trailing dot missed the "+
			"allowlist and the connection left the sandbox directly", got)
	}
}

// The route may be the one written with the dot, and the client the one
// without. Then the route has to match itself.
func TestTrailingDotInTheRouteStaysInsideTheTunnel(t *testing.T) {
	if got := routedThroughSpelling(t, "localhost.", "localhost"); !strings.HasPrefix(got, "controlplane:") {
		t.Fatalf("answer = %q, want the controlplane's target", got)
	}
}

// net.Dial reads ":0443" as port 443, so the allowlist must not read it as a
// different route.
func TestZeroPaddedPortStaysInsideTheTunnel(t *testing.T) {
	tunnelSide, _ := tcpEcho(t, "controlplane")
	direct, _ := tcpEcho(t, "direct")
	_, port, _ := net.SplitHostPort(direct)

	routerAddr, client := sandbox(t)
	if err := client.Proxy().ForwardTo("localhost:"+port, tunnelSide); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	conn := socksDial(t, routerAddr, "localhost:0"+port)
	if got := ask(t, conn, "hi"); !strings.HasPrefix(got, "controlplane:") {
		t.Fatalf("answer = %q, want the controlplane's target: a zero-padded port missed the "+
			"allowlist and the connection left the sandbox directly", got)
	}
}
