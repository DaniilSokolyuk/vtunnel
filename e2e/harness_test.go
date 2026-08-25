package e2e_test

// The production topology, assembled in one process.
//
//	app ──► egress proxy ──► WS tunnel ──► MITM proxy ──► upstream
//	        (sandbox side)                 (controlplane side)
//
// Every test in this module drives that whole chain rather than a MITMProxy on
// its own, because the bugs worth catching here live in the seams: a route that
// has not crossed the tunnel yet, a protocol negotiated on one leg and not the
// other, a body that arrives whole instead of in pieces.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/vivid-money/vtunnel"
)

var upgrader = websocket.Upgrader{
	CheckOrigin:       func(r *http.Request) bool { return true },
	EnableCompression: true,
	Subprotocols:      []string{"vtunnel.matrix"},
}

func wsURL(ts *httptest.Server) string {
	return "ws" + strings.TrimPrefix(ts.URL, "http")
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// connectThroughProxy is the agent's side of the egress proxy: CONNECT, then the
// raw stream. Tests that need to speak a protocol the http package will not
// build for them start here.
func connectThroughProxy(ctx context.Context, proxyAddr, target string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: target},
		Host:   target,
		Header: http.Header{},
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("CONNECT %s: %s", target, resp.Status)
	}
	return conn, nil
}

func generateTestCA(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "vtunnel test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
}

// ---------------------------------------------------------------------------
// The chain
// ---------------------------------------------------------------------------

// chain is the assembled topology. Tests declare routes on proxy — the
// controlplane's MITM proxy — and point their clients at proxyAddr, the
// sandbox's egress proxy, exactly as an agent would.
type chain struct {
	proxyAddr string
	proxy     *vtunnel.MITMProxy
	caPool    *x509.CertPool
}

// newChain brings up both halves and the tunnel between them. setup runs on the
// controlplane proxy before the tunnel is dialled, which is where anything that
// must be in place before the first request goes — SetTransportTLSConfig, most
// of all, since a route can be served the instant the tunnel comes up.
func newChain(t *testing.T, setup func(*vtunnel.MITMProxy)) *chain {
	t.Helper()

	ca := generateTestCA(t)

	sandbox := vtunnel.NewServer()
	t.Cleanup(func() { sandbox.Close() })

	proxyAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := sandbox.StartProxy(proxyAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		sandbox.HandleWebSocket(conn)
	}))
	t.Cleanup(ts.Close)

	client := vtunnel.NewClient(wsURL(ts), vtunnel.WithMitm(ca))
	t.Cleanup(func() { client.Close() })
	if setup != nil {
		setup(client.Proxy())
	}
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	caPool := x509.NewCertPool()
	caLeaf, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	caPool.AddCert(caLeaf)

	return &chain{proxyAddr: proxyAddr, proxy: client.Proxy(), caPool: caPool}
}

// waitRoute blocks until a route declared on the controlplane has crossed the
// tunnel. Declaring it is local and instant; the sandbox learns about it over
// the wire, so the first request can otherwise beat it there and be refused.
func (c *chain) waitRoute(t *testing.T, host string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := connectThroughProxy(ctx, c.proxyAddr, host+":443")
		cancel()
		if err == nil {
			conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("route %s never reached the sandbox: %v", host, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
