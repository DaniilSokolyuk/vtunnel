package vtunnel

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// A MITMProxy owns every piece of state it uses — routes, CA, certificate
// cache, upstream transports, h2c probes, exclusions, lifecycle — so a process
// may run as many as it likes side by side. The only package-level state left
// is the SSLKEYLOGFILE handle, which is one file per process by definition, and
// a byte-buffer pool.
//
// Each proxy here holds a different CA, and each client trusts only its own, so
// a leaf minted by the wrong instance fails the handshake rather than quietly
// answering: cross-talk shows up as an error, not as a passing assertion.
func TestManyProxiesRunSideBySide(t *testing.T) {
	const count = 4

	type instance struct {
		proxy  *MITMProxy
		client *http.Client
		want   string
	}

	instances := make([]*instance, count)
	for i := range instances {
		want := fmt.Sprintf("upstream-%d", i)
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "%s:%s", want, r.Header.Get("X-Which"))
		}))
		t.Cleanup(upstream.Close)

		ca := generateProxyTestCA(t)
		p := NewMITMProxy(WithMitmCA(ca))
		// Same domain on every instance: if any state were shared, one of these
		// routes would win for all of them.
		if err := p.ForwardTo("shared.corp", upstream.Listener.Addr().String(),
			WithHeader("X-Which", fmt.Sprintf("%d", i))); err != nil {
			t.Fatalf("ForwardTo %d: %v", i, err)
		}
		if err := p.Start("127.0.0.1:0"); err != nil {
			t.Fatalf("Start %d: %v", i, err)
		}
		t.Cleanup(p.Close)

		instances[i] = &instance{
			proxy:  p,
			client: proxyHTTPClient(p.Addr().String(), ca, false),
			want:   fmt.Sprintf("%s:%d", want, i),
		}
	}

	// Concurrently, so any shared map or transport would race as well as answer
	// wrongly — this test runs under -race like the rest.
	var wg sync.WaitGroup
	for i, inst := range instances {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := inst.client.Get("https://shared.corp/")
			if err != nil {
				t.Errorf("proxy %d: GET: %v", i, err)
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if string(body) != inst.want {
				t.Errorf("proxy %d answered %q, want %q", i, body, inst.want)
			}
		}()
	}
	wg.Wait()

	// Closing one must not disturb the others: the listener, the tracked
	// connections and the transport pool it drops are all its own.
	instances[0].proxy.Close()
	if _, err := instances[0].client.Get("https://shared.corp/"); err == nil {
		t.Error("the closed proxy still served a request")
	}
	for i, inst := range instances[1:] {
		resp, err := inst.client.Get("https://shared.corp/")
		if err != nil {
			t.Errorf("proxy %d stopped working after another was closed: %v", i+1, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != inst.want {
			t.Errorf("proxy %d answered %q after another was closed, want %q", i+1, body, inst.want)
		}
	}
}

// Two proxies with different upstream TLS settings must not end up sharing a
// transport: the cache that stops per-request cloning is per instance, and a
// shared one would hand the wrong root pool — or the wrong client certificate —
// to whichever asked second.
func TestUpstreamTransportCacheIsPerProxy(t *testing.T) {
	rt := route{target: "api.corp:443", tlsHost: "api.corp"}

	first := NewMITMProxy()
	defer first.Close()
	second := NewMITMProxy()
	defer second.Close()

	a, _, releaseA := first.upstreamTransport(rt, nil, false)
	defer releaseA()
	b, _, releaseB := second.upstreamTransport(rt, nil, false)
	defer releaseB()

	if a == b {
		t.Fatal("two proxies share one upstream transport")
	}
}

// The certificate cache is built per proxy, so a leaf signed by one CA is never
// handed out by a proxy holding another.
func TestCertCacheIsPerProxy(t *testing.T) {
	first := NewMITMProxy(WithMitmCA(generateProxyTestCA(t)))
	second := NewMITMProxy(WithMitmCA(generateProxyTestCA(t)))

	firstCerts, err := first.certs()
	if err != nil {
		t.Fatalf("first certs: %v", err)
	}
	secondCerts, err := second.certs()
	if err != nil {
		t.Fatalf("second certs: %v", err)
	}
	if firstCerts == secondCerts {
		t.Fatal("two proxies share one certificate cache")
	}

	hello := &tls.ClientHelloInfo{ServerName: "api.corp"}
	leafA, err := firstCerts.getCert(hello, "")
	if err != nil {
		t.Fatalf("first getCert: %v", err)
	}
	leafB, err := secondCerts.getCert(hello, "")
	if err != nil {
		t.Fatalf("second getCert: %v", err)
	}

	// The chain each leaf carries ends in its own CA. Comparing the subject
	// would prove nothing — the test CAs share a common name — so the CA
	// certificate itself is what is checked.
	if bytes.Equal(leafA.Certificate[1], leafB.Certificate[1]) {
		t.Fatal("both proxies minted a leaf signed by the same CA")
	}
	if bytes.Equal(leafA.Certificate[0], leafB.Certificate[0]) {
		t.Fatal("both proxies handed out the same leaf")
	}
}

// Exclusions are learned per proxy: one instance discovering that a domain
// pins certificates must not stop another from intercepting it.
func TestMITMExceptionsArePerProxy(t *testing.T) {
	first := NewMITMProxy()
	second := NewMITMProxy()

	first.MITMExceptions("pinned.corp")

	if blocked, _ := first.mitmBlocked("pinned.corp:443"); !blocked {
		t.Fatal("the proxy that was given the exception does not hold it")
	}
	if blocked, _ := second.mitmBlocked("pinned.corp:443"); blocked {
		t.Fatal("an exception configured on one proxy reached another")
	}
}

// Two proxies may listen at once, and neither Start nor Close reaches past its
// own instance.
func TestProxiesListenIndependently(t *testing.T) {
	first := NewMITMProxy()
	if err := first.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	defer first.Close()

	second := NewMITMProxy()
	if err := second.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	defer second.Close()

	if first.Addr().String() == second.Addr().String() {
		t.Fatal("both proxies claim the same address")
	}

	first.Close()
	if first.closed() == second.closed() {
		t.Fatal("closing one proxy changed the other's state")
	}

	// The one still up keeps answering.
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: second.Addr().String()}),
		},
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "still here")
	}))
	defer upstream.Close()

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("the surviving proxy stopped serving: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "still here" {
		t.Fatalf("body = %q", body)
	}
}
