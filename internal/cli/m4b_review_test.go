package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HarnageaGabriel/scadenza/internal/renewal"
)

// TestScanManualRenewalNormalizedConfigKey pins M4b review finding 7: a renewal
// key written with a wildcard or a trailing dot is normalized with the shared
// domain normalizer, so it still matches the certificate name instead of
// silently dropping the manual declaration.
func TestScanManualRenewalNormalizedConfigKey(t *testing.T) {
	server := certSpotterServer(t, ctOnlyFixture())
	directory := t.TempDir()
	path := filepath.Join(directory, "scadenza.yaml")
	if err := os.WriteFile(path, []byte("version: 1\ndomains: [example.com]\nrenewal:\n  \"*.Example.COM.\": manual\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := execute(context.Background(), []string{"scan", "--config", path, "--source", "certspotter", "--format", "json"}, &stdout, &stderr, scanDependencies(server.URL, ctOnlyProber())); code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
	}
	document := decodeM4b(t, stdout.Bytes())
	if len(document.Certificates) == 0 {
		t.Fatal("no certificates in the scan output")
	}
	for _, certificate := range document.Certificates {
		if certificate.Renewal.Mode != renewal.ModeManual {
			t.Errorf("mode = %s, want manual for %s", certificate.Renewal.Mode, certificate.Fingerprint)
		}
	}
}

// TestScanRejectsMalformedRenewalKey pins the other half of finding 7: a
// malformed key is a usage error, not a silently ignored declaration.
func TestScanRejectsMalformedRenewalKey(t *testing.T) {
	server := certSpotterServer(t, ctOnlyFixture())
	directory := t.TempDir()
	path := filepath.Join(directory, "scadenza.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nrenewal:\n  \"exa..mple.com\": manual\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := execute(context.Background(), []string{"scan", "--config", path, "--source", "certspotter", "--format", "json"}, &stdout, &stderr, scanDependencies(server.URL, ctOnlyProber())); code != ExitUsageError {
		t.Fatalf("exit = %d, want %d; stderr=%s", code, ExitUsageError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "SCD-0022") {
		t.Errorf("stderr = %q, want SCD-0022", stderr.String())
	}
}

// TestScanAcceptsRenewalConfigInvalidFailOn pins M4b review finding 2: the new
// kind is accepted by --fail-on even though it is not on by default.
func TestScanAcceptsRenewalConfigInvalidFailOn(t *testing.T) {
	server := certSpotterServer(t, ctOnlyFixture())
	var stdout, stderr bytes.Buffer
	if code := execute(context.Background(), []string{"scan", "--domain", "example.com", "--source", "certspotter", "--fail-on", "renewal-config-invalid", "--format", "json"}, &stdout, &stderr, scanDependencies(server.URL, ctOnlyProber())); code == ExitUsageError {
		t.Fatalf("renewal-config-invalid rejected as a --fail-on kind; stderr=%s", stderr.String())
	}
}
