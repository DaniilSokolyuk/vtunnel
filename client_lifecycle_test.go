package vtunnel

// What a Client owns, and what it must therefore clean up or refuse.

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The tunnel port on the sandbox is pointed at the whole controlplane proxy,
// not at one forward target. A process inside the sandbox that dials that port
// directly never passes through the EgressProxy or its allowlist — and a proxy that
// dials whatever it is asked for would hand it the controlplane's entire
// network, cloud metadata endpoint included.
//
// A client-owned proxy therefore refuses unrouted domains by default. Dialling
// on demand is right for the sandbox-side proxy and wrong here.
func TestClientOwnedProxyRefusesUnroutedDomainsByDefault(t *testing.T) {
	// Somewhere only the "controlplane" can reach.
	private := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secret"))
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go private.Serve(ln)
	defer private.Close()

	for _, tc := range []struct {
		name   string
		client *Client
	}{
		{name: "no options", client: NewClient("ws://unused/")},
		{name: "with interception", client: NewClient("ws://unused/", WithMitm(testCA(t, "client CA")))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy := tc.client.Proxy()
			if err := proxy.Start("127.0.0.1:0"); err != nil {
				t.Fatalf("Start: %v", err)
			}
			defer proxy.Close()

			// Exactly what a process in the sandbox would do with the tunnel port.
			conn, err := net.DialTimeout("tcp", proxy.Addr().String(), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))

			req, _ := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/", nil)
			if err := req.WriteProxy(conn); err != nil {
				t.Fatalf("write: %v", err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), req)
			if err != nil {
				return // refused by closing: acceptable
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Fatal("the client's proxy relayed to an unrouted address: " +
					"anything in the sandbox can reach the controlplane's whole network through it")
			}
		})
	}
}

// replayForwards only checked that routes exist, so after a failed startProxy —
// a taken port, a refused bind, a CA that would not load — the reconnect
// goroutine dereferenced a nil Addr and took the whole controlplane down with
// it. That goroutine has no recover.
func TestSendEgressListenSurvivesUnstartedProxy(t *testing.T) {
	// A CA that cannot be parsed makes Start fail before it ever listens, which
	// is the shape of every real cause.
	broken := tls.Certificate{Certificate: [][]byte{[]byte("not a certificate")}}
	c := NewClient("ws://unused/", WithMitm(broken))
	c.Proxy().ForwardTo("api.corp", "localhost:9999")

	if c.Proxy().Addr() != nil {
		t.Fatal("the proxy started despite an unusable CA; pick another way to fail Start")
	}

	err := c.sendEgressListen(nil)
	if err == nil {
		t.Fatal("sendEgressListen accepted a proxy with no address")
	}
	if !strings.Contains(err.Error(), "proxy") {
		t.Fatalf("err = %v, want it to name the proxy", err)
	}
}

// Close tore down the SSH connection and left the proxy listening — with every
// configured credential still attached. The documented `defer client.Close()`
// therefore leaked a listener and a goroutine per client, and anything local
// could still reach a closed client's proxy and have headers injected for it.
func TestClientCloseStopsTheProxyItStarted(t *testing.T) {
	c := NewClient("ws://unused/", WithMitm(testCA(t, "close CA")))
	if err := c.startProxy(); err != nil {
		t.Fatalf("startProxy: %v", err)
	}
	addr := c.Proxy().Addr()
	if addr == nil {
		t.Fatal("proxy did not start")
	}

	c.Close()

	conn, err := net.DialTimeout("tcp", addr.String(), time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("the proxy is still accepting connections after Client.Close")
	}
}

// A proxy handed in through WithProxy belongs to the caller: the client did not
// start it and must not stop it.
func TestClientCloseLeavesACallerOwnedProxyAlone(t *testing.T) {
	proxy := NewMITMProxy(WithMitmCA(testCA(t, "caller CA")))
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxy.Close()
	addr := proxy.Addr().String()

	c := NewClient("ws://unused/", WithProxy(proxy))
	c.Close()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("the client closed a proxy it did not start: %v", err)
	}
	conn.Close()
}
