package vtunnel

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// tlsKeyLogWriter resolves once per process, so each case has to reset the guard
// before it can observe the other outcome.
func resetKeyLogResolution() {
	keyLogOnce = sync.Once{}
	keyLogDest = nil
}

// With the variable unset, tls.Config.KeyLogWriter must end up nil rather than a
// writer pointing nowhere: a non-nil writer would make every handshake in the
// process spend work serialising secrets that go on to be discarded.
func TestTLSKeyLogWriterOffByDefault(t *testing.T) {
	resetKeyLogResolution()
	t.Cleanup(resetKeyLogResolution)

	t.Setenv("SSLKEYLOGFILE", "")

	if w := tlsKeyLogWriter(); w != nil {
		t.Fatalf("KeyLogWriter = %v with SSLKEYLOGFILE unset, want nil", w)
	}
}

// With the variable set, the file must be created and appended to. The mode
// matters as much as the content: these are session keys, so a world-readable
// file would hand the traffic to every account on the machine.
func TestTLSKeyLogWriterWritesToFile(t *testing.T) {
	resetKeyLogResolution()
	t.Cleanup(resetKeyLogResolution)

	path := filepath.Join(t.TempDir(), "keys.log")
	t.Setenv("SSLKEYLOGFILE", path)

	w := tlsKeyLogWriter()
	if w == nil {
		t.Fatal("KeyLogWriter is nil with SSLKEYLOGFILE set")
	}
	if _, err := w.Write([]byte("CLIENT_RANDOM abc def\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key log mode = %o, want 600 — session keys must not be readable by others", perm)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != "CLIENT_RANDOM abc def\n" {
		t.Fatalf("key log content = %q", body)
	}

	// Resolution is cached, so a second call must hand back the same destination
	// instead of reopening and truncating.
	if again := tlsKeyLogWriter(); again != w {
		t.Fatal("second call returned a different writer; the resolution is not cached")
	}
}

// An unusable path must disable logging, not take the proxy down with it: a
// mistyped variable should cost debuggability and nothing else.
func TestTLSKeyLogWriterSurvivesBadPath(t *testing.T) {
	resetKeyLogResolution()
	t.Cleanup(resetKeyLogResolution)

	// A path under a file (rather than a directory) cannot be opened.
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	t.Setenv("SSLKEYLOGFILE", filepath.Join(blocker, "keys.log"))

	if w := tlsKeyLogWriter(); w != nil {
		t.Fatalf("KeyLogWriter = %v for an unopenable path, want nil", w)
	}
}
