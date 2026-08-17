package vtunnel_test

// These tests drive MITMProxy directly, without a tunnel, to cover proxy
// behaviour in isolation. That is not how the library is normally used: see
// doc.go and example_test.go for the Client.Forward entry point, and
// egress_e2e_test.go for the full sandbox-to-controlplane path.

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/vivid-money/vtunnel"
)

// setupBareRepo creates a bare git repo with one commit, runs update-server-info
// so it can be served via dumb HTTP.
func setupBareRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bareDir := filepath.Join(dir, "repo.git")
	workDir := filepath.Join(dir, "work")

	run := func(args ...string) {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %s\n%s", args, err, out)
		}
	}

	run("git", "init", "--bare", bareDir)
	run("git", "clone", bareDir, workDir)
	os.WriteFile(filepath.Join(workDir, "hello.txt"), []byte("hello from git\n"), 0644)
	run("git", "-C", workDir, "add", "hello.txt")
	run("git", "-C", workDir, "-c", "user.name=Test", "-c", "user.email=test@test.com", "commit", "-m", "initial")
	run("git", "-C", workDir, "push", "origin", "master")
	run("git", "-C", bareDir, "update-server-info")

	return bareDir
}

func TestProxyGitCloneHTTP(t *testing.T) {
	bareDir := setupBareRepo(t)

	// Serve the bare repo over plain HTTP (dumb protocol)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go http.Serve(ln, http.FileServer(http.Dir(filepath.Dir(bareDir))))

	gitAddr := ln.Addr().String()

	proxy := vtunnel.NewMITMProxy()
	proxyPort := freePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if err := proxy.Start(proxyAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer proxy.Close()

	proxy.ForwardTo("gitserver.test:80", gitAddr)

	cloneDir := filepath.Join(t.TempDir(), "clone")

	cmd := exec.Command("git", "clone", "http://gitserver.test/repo.git", cloneDir)
	cmd.Env = append(os.Environ(),
		"http_proxy=http://"+proxyAddr,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git clone via HTTP proxy failed: %v\n%s", err, out)
	}
	t.Logf("git clone output:\n%s", out)

	content, err := os.ReadFile(filepath.Join(cloneDir, "hello.txt"))
	if err != nil {
		t.Fatalf("Read cloned file: %v", err)
	}
	if string(content) != "hello from git\n" {
		t.Fatalf("Unexpected content: %q", content)
	}
}

func TestProxyGitCloneCONNECTMitm(t *testing.T) {
	bareDir := setupBareRepo(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go http.Serve(ln, http.FileServer(http.Dir(filepath.Dir(bareDir))))

	gitAddr := ln.Addr().String()

	ca := generateTestCA(t)
	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	proxyPort := freePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if err := proxy.Start(proxyAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer proxy.Close()

	proxy.ForwardTo("gitsecure.test:443", gitAddr)

	cloneDir := filepath.Join(t.TempDir(), "clone-mitm")

	cmd := exec.Command("git", "clone", "https://gitsecure.test/repo.git", cloneDir)
	cmd.Env = append(os.Environ(),
		"https_proxy=http://"+proxyAddr,
		"GIT_SSL_NO_VERIFY=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git clone via HTTPS CONNECT+MITM proxy failed: %v\n%s", err, out)
	}
	t.Logf("git clone output:\n%s", out)

	content, err := os.ReadFile(filepath.Join(cloneDir, "hello.txt"))
	if err != nil {
		t.Fatalf("Read cloned file: %v", err)
	}
	if string(content) != "hello from git\n" {
		t.Fatalf("Unexpected content: %q", content)
	}
}

func TestProxyGitCloneCONNECTMitmHTTP2(t *testing.T) {
	bareDir := setupBareRepo(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go http.Serve(ln, http.FileServer(http.Dir(filepath.Dir(bareDir))))

	gitAddr := ln.Addr().String()

	ca := generateTestCA(t)
	proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
	proxyPort := freePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if err := proxy.Start(proxyAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	defer proxy.Close()

	proxy.ForwardTo("gith2.test:443", gitAddr)

	cloneDir := filepath.Join(t.TempDir(), "clone-mitm-h2")

	cmd := exec.Command("git",
		"-c", "http.version=HTTP/2",
		"clone", "https://gith2.test/repo.git", cloneDir,
	)
	cmd.Env = append(os.Environ(),
		"https_proxy=http://"+proxyAddr,
		"GIT_SSL_NO_VERIFY=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git clone via HTTPS CONNECT+MITM (HTTP/2) proxy failed: %v\n%s", err, out)
	}
	t.Logf("git clone HTTP/2 output:\n%s", out)

	content, err := os.ReadFile(filepath.Join(cloneDir, "hello.txt"))
	if err != nil {
		t.Fatalf("Read cloned file: %v", err)
	}
	if string(content) != "hello from git\n" {
		t.Fatalf("Unexpected content: %q", content)
	}
}
