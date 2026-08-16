package vtunnel

// Three small ones on the client's own state.

import (
	"net"
	"sync"
	"testing"
	"time"
)

// proxyOwned is written by startProxy — which runs on whatever goroutine
// declared a route — and read by Close, on the owner's. That is a data race in
// the plain sense, and the consequence when it goes the wrong way is a proxy
// holding every configured credential left listening behind a closed client.
//
// It never showed up because CI ran without -race. It does now.
func TestProxyOwnershipIsRaceFree(t *testing.T) {
	for range 20 {
		c := NewClient("ws://unused/")

		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); c.startProxy() }()
		go func() { defer wg.Done(); c.Close() }()
		wg.Wait()

		c.Proxy().Close()
	}
}

// A proxy can be shared between clients — WithProxy says so in as many words —
// and each of them subscribes to route changes to keep its own sandbox in step.
// One callback slot meant the second client silently unsubscribed the first,
// whose allowlist then stopped being synced with no error anywhere.
func TestOnChangeNotifiesEverySubscriber(t *testing.T) {
	proxy := NewMITMProxy()

	var mu sync.Mutex
	fired := map[string]int{}
	note := func(name string) func() {
		return func() {
			mu.Lock()
			fired[name]++
			mu.Unlock()
		}
	}

	proxy.OnChange(note("first"))
	proxy.OnChange(note("second"))

	if err := proxy.ForwardTo("api.corp", "localhost:9999"); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	proxy.Remove("api.corp")

	mu.Lock()
	defer mu.Unlock()
	for _, name := range []string{"first", "second"} {
		if fired[name] != 2 {
			t.Errorf("%s subscriber fired %d times, want 2 (one add, one remove): "+
				"a second subscriber replaced the first, so one client's sandbox stopped "+
				"hearing about route changes", name, fired[name])
		}
	}
}

// "tls://host" says the upstream speaks TLS. Without a port net.SplitHostPort
// fails, and the intent was dropped on the floor: the request then went out on
// port 80, in the clear, with the configured credential attached.
func TestParseForwardTargetDefaultsTLSToPort443(t *testing.T) {
	cases := []struct {
		in          string
		wantTarget  string
		wantTLSHost string
		wantTLS     bool
	}{
		{in: "tls://api.corp", wantTarget: "api.corp:443", wantTLSHost: "api.corp", wantTLS: true},
		{in: "tls://api.corp:8443", wantTarget: "api.corp:8443", wantTLSHost: "api.corp", wantTLS: true},
		{in: "tls://10.0.0.7:443", wantTarget: "10.0.0.7:443", wantTLSHost: "10.0.0.7", wantTLS: true},
		{in: "api.corp:443", wantTarget: "api.corp:443", wantTLSHost: "api.corp", wantTLS: true},
		{in: "localhost:8080", wantTarget: "localhost:8080"},
	}

	for _, tc := range cases {
		target, tlsHost, isTLS := parseForwardTarget(tc.in)
		if target != tc.wantTarget || tlsHost != tc.wantTLSHost || isTLS != tc.wantTLS {
			t.Errorf("parseForwardTarget(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.in, target, tlsHost, isTLS, tc.wantTarget, tc.wantTLSHost, tc.wantTLS)
		}
	}
}

// The same for a raw forward: dialTarget must not quietly dial :80 for a target
// that asked for TLS.
func TestDialTargetDefaultsTLSToPort443(t *testing.T) {
	c := NewClient("ws://unused/")

	// Nothing is listening on :443 here; what is asserted is where it tried.
	_, err := c.dialTarget("tls://127.0.0.1")
	if err == nil {
		t.Skip("something is listening on 127.0.0.1:443")
	}
	if !containsPort(err.Error(), "443") {
		t.Fatalf("dial error = %v, want it to name port 443", err)
	}
}

func containsPort(msg, port string) bool {
	for i := 0; i+len(port) <= len(msg); i++ {
		if msg[i:i+len(port)] == port {
			return true
		}
	}
	return false
}

// A forward whose target is TLS on the default port still reaches it.
func TestForwardToTLSTargetWithoutPort(t *testing.T) {
	proxy := NewMITMProxy()
	if err := proxy.ForwardTo("api.corp", "tls://upstream.internal"); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}

	rt, ok := proxy.resolveDomain("api.corp:443")
	if !ok {
		t.Fatal("no route for api.corp:443")
	}
	if rt.target != "upstream.internal:443" {
		t.Errorf("target = %q, want upstream.internal:443", rt.target)
	}
	if rt.tlsHost != "upstream.internal" {
		t.Errorf("tlsHost = %q, want upstream.internal: without it the request goes out in "+
			"the clear with the injected credential attached", rt.tlsHost)
	}
}

// startProxy must not be tripped up by a caller-supplied proxy that is already
// listening, which is the shape WithProxy documents.
func TestStartProxyLeavesACallerStartedProxyAlone(t *testing.T) {
	proxy := NewMITMProxy()
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxy.Close()
	addr := proxy.Addr()

	c := NewClient("ws://unused/", WithProxy(proxy))
	if err := c.startProxy(); err != nil {
		t.Fatalf("startProxy: %v", err)
	}
	if proxy.Addr() != addr {
		t.Fatal("startProxy restarted a proxy that was already listening")
	}

	c.Close()
	conn, err := net.DialTimeout("tcp", addr.String(), time.Second)
	if err != nil {
		t.Fatalf("the client closed a proxy it did not start: %v", err)
	}
	conn.Close()
}
