package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The CA file holds a key that can mint certificates every sandbox trusts.
// It must be created private, and reused rather than regenerated — a new CA on
// every start would silently invalidate the certificate installed in sandboxes.
func TestLoadOrCreateCA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "ca.pem")

	first, err := loadOrCreateCA(path)
	if err != nil {
		t.Fatalf("loadOrCreateCA: %v", err)
	}
	if !first.Leaf.IsCA {
		t.Fatal("generated certificate is not a CA")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat CA: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("CA file mode = %04o, want 0600", perm)
	}

	second, err := loadOrCreateCA(path)
	if err != nil {
		t.Fatalf("loadOrCreateCA (reuse): %v", err)
	}
	if first.Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) != 0 {
		t.Fatal("CA was regenerated on second load; sandboxes would stop trusting it")
	}

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	if !strings.Contains(string(blob), "PRIVATE KEY") {
		t.Fatal("stored CA has no private key; it cannot sign")
	}
}

// A corrupt or non-CA file must fail loudly instead of falling back to
// generating a fresh CA over the user's file.
func TestLoadOrCreateCARejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := loadOrCreateCA(path); err == nil {
		t.Fatal("loadOrCreateCA accepted a non-PEM file")
	}
	blob, _ := os.ReadFile(path)
	if string(blob) != "not a pem" {
		t.Fatal("loadOrCreateCA overwrote an existing file it could not parse")
	}
}

// vtunnel ca writes the two halves as separate files, so neither redirection
// nor a second command is needed to get the certificate — and so the private
// half cannot be handed out by accident.
func TestRunCAWritesBothHalves(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")

	runCA([]string{"-mitm-ca", caPath})

	pair, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read CA pair: %v", err)
	}
	if !strings.Contains(string(pair), "PRIVATE KEY") ||
		!strings.Contains(string(pair), "BEGIN CERTIFICATE") {
		t.Fatal("CA pair must hold both the key and the certificate")
	}

	certPath := filepath.Join(dir, "ca.crt")
	cert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("certificate not written next to the CA: %v", err)
	}
	if strings.Contains(string(cert), "PRIVATE KEY") {
		t.Fatalf("exported certificate leaked the private key:\n%s", cert)
	}
	if !strings.Contains(string(cert), "BEGIN CERTIFICATE") {
		t.Fatalf("exported file holds no certificate:\n%s", cert)
	}

	if mode := statMode(t, caPath); mode != 0o600 {
		t.Fatalf("CA pair mode = %04o, want 0600", mode)
	}
	if mode := statMode(t, certPath); mode != 0o644 {
		t.Fatalf("certificate mode = %04o, want 0644", mode)
	}

	// Re-running must re-export, not mint a new CA: sandboxes already trust
	// the old one.
	runCA([]string{"-mitm-ca", caPath})
	again, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read CA pair: %v", err)
	}
	if string(again) != string(pair) {
		t.Fatal("second run replaced the CA")
	}
}

func statMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}

// Review 2. `vtunnel ca -mitm-ca ca.crt` used to compute the export path by
// swapping the extension for .crt — which, for a CA already named .crt, is the
// same file. The certificate half then overwrote the pair, destroying the
// private key with no warning and no way back: every sandbox trusting that CA
// needs a new one.
func TestCertExportPathNeverOverwritesTheCA(t *testing.T) {
	dir := t.TempDir()

	for _, tc := range []struct {
		name    string
		caPath  string
		out     string
		want    string
		wantErr bool
	}{
		{
			name:   "conventional pair name",
			caPath: filepath.Join(dir, "ca.pem"),
			want:   filepath.Join(dir, "ca.crt"),
		},
		{
			name:   "explicit destination",
			caPath: filepath.Join(dir, "ca.pem"),
			out:    filepath.Join(dir, "elsewhere.crt"),
			want:   filepath.Join(dir, "elsewhere.crt"),
		},
		{
			name:    "CA already named .crt",
			caPath:  filepath.Join(dir, "ca.crt"),
			wantErr: true,
		},
		{
			name:    "explicit destination is the CA itself",
			caPath:  filepath.Join(dir, "ca.pem"),
			out:     filepath.Join(dir, "ca.pem"),
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := certExportPath(tc.caPath, tc.out)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("certExportPath(%q, %q) = %q, want a refusal: it would destroy the key",
						tc.caPath, tc.out, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("certExportPath(%q, %q): %v", tc.caPath, tc.out, err)
			}
			if got != tc.want {
				t.Fatalf("certExportPath(%q, %q) = %q, want %q", tc.caPath, tc.out, got, tc.want)
			}
		})
	}
}
