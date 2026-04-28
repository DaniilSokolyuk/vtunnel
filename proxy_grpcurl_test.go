package vtunnel_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/vivid-money/vtunnel"
)

const grpcTestHost = "grpcb.in"

func TestProxyGrpcurlMITMTunnel(t *testing.T) {
	if _, err := exec.LookPath("grpcurl"); err != nil {
		t.Skip("grpcurl not in PATH")
	}

	ca := generateTestCA(t)
	server := vtunnel.NewServer(vtunnel.WithProxyMitmCA(ca))

	proxyPort := freePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if err := server.StartProxy(proxyAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer server.CloseProxy()

	tunnelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		server.HandleConn(conn)
	}))
	defer tunnelServer.Close()

	client := vtunnel.NewClient(wsURL(tunnelServer))
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	target := grpcTestHost + ":443"
	if err := client.Forward(target, target); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Sanity check: plain HTTPS through MITM tunnel works.
	proxyURL := &url.URL{Scheme: "http", Host: proxyAddr}
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := httpClient.Get("https://" + grpcTestHost + "/")
	if err != nil {
		t.Fatalf("HTTPS sanity check failed: %v", err)
	}
	resp.Body.Close()
	t.Logf("HTTPS sanity check: %d", resp.StatusCode)

	// grpcurl list through the MITM tunnel proxy.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "grpcurl", "-insecure", target, "list")
	cmd.Env = append(os.Environ(),
		"https_proxy="+proxyURL.String(),
		"HTTPS_PROXY="+proxyURL.String(),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("grpcurl list failed: %v\n%s", err, out)
	}
	t.Logf("grpcurl list (%d services):\n%s", strings.Count(string(out), "\n"), out)

	if !strings.Contains(string(out), "grpcbin.GRPCBin") {
		t.Fatal("expected grpcbin.GRPCBin in grpcurl output")
	}
}
