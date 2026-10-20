package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/inventory"
	"github.com/HarnageaGabriel/scadenza/internal/tlsprobe"
)

// ctOnlyFixture has two in-scope certificates. The live handshake presents the
// second, so the first is ct_only and there is no live_only finding, which lets
// the failure policy be tested in isolation.
func ctOnlyFixture() string {
	return `[
{"id":"1","cert_sha256":"` + strings.Repeat("a", 64) + `","dns_names":["api.example.com"],"issuer":{"name":"CN=Example Root"},"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","revoked":false},
{"id":"2","cert_sha256":"` + strings.Repeat("b", 64) + `","dns_names":["www.example.com"],"issuer":{"name":"CN=Example Root"},"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","revoked":false}
]`
}

func ctOnlyProber() fakeProber {
	return fakeProber{results: map[string]tlsprobe.Result{
		"api.example.com:443": {Fingerprint: strings.Repeat("b", 64), Names: []string{"www.example.com"}, Issuer: "CN=Example Root", NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), Trusted: true},
		"www.example.com:443": {Fingerprint: strings.Repeat("b", 64), Names: []string{"www.example.com"}, Issuer: "CN=Example Root", NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), Trusted: true},
	}}
}

func TestBlockingFindingHonorsFailOn(t *testing.T) {
	findings := []inventory.Finding{
		{Kind: inventory.KindCTOnly},
		{Kind: inventory.KindExceeds100D},
		{Kind: inventory.KindNotCompliantAtIssuance},
	}
	cases := []struct {
		name   string
		failOn []string
		want   bool
	}{
		{"default policy ignores ct_only and exceeds-100d", []string{"live_only", "not-compliant-at-issuance"}, true},
		{"none disables exit 3", []string{"none"}, false},
		{"ct_only selected", []string{"ct_only"}, true},
		{"exceeds-100d selected", []string{"exceeds-100d"}, true},
		{"unselected kinds do not block", []string{"live_only"}, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := blockingFinding(test.failOn, findings); got != test.want {
				t.Fatalf("blockingFinding(%v) = %v, want %v", test.failOn, got, test.want)
			}
		})
	}
}

func TestScanCTOnlyRespectsFailOn(t *testing.T) {
	server := certSpotterServer(t, ctOnlyFixture())
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"default: ct_only reported but not failing", []string{"scan", "--domain", "example.com", "--source", "certspotter", "--format", "json"}, ExitOK},
		{"ct_only selected", []string{"scan", "--domain", "example.com", "--source", "certspotter", "--fail-on", "ct_only", "--format", "json"}, ExitFindingsPresent},
		{"none disables exit 3", []string{"scan", "--domain", "example.com", "--source", "certspotter", "--fail-on", "none", "--format", "json"}, ExitOK},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := execute(context.Background(), test.args, &stdout, &stderr, scanDependencies(server.URL, ctOnlyProber()))
			if code != test.want {
				t.Fatalf("exit = %d, want %d; stderr=%s", code, test.want, stderr.String())
			}
			if !strings.Contains(stdout.String(), `"coverage"`) {
				t.Errorf("output has no coverage section: %s", stdout.String())
			}
		})
	}
}

// TestScanExitPrecedence checks the documented order: 2 usage > 4 all sources
// unavailable > 3 blocking finding > 5 incomplete scan > 0.
func TestScanExitPrecedence(t *testing.T) {
	server := certSpotterServer(t, scanCTFixture())
	cases := []struct {
		name string
		url  string
		args []string
		want int
	}{
		{"blocking finding beats strict", server.URL, []string{"scan", "--domain", "example.com", "--source", "certspotter", "--strict", "--min-coverage", "100", "--format", "json"}, ExitFindingsPresent},
		{"strict exits 5 when no blocking finding", server.URL, []string{"scan", "--domain", "example.com", "--source", "certspotter", "--fail-on", "none", "--strict", "--format", "json"}, ExitIncompleteScan},
		{"min-coverage exits 5 when no blocking finding", server.URL, []string{"scan", "--domain", "example.com", "--source", "certspotter", "--fail-on", "none", "--min-coverage", "100", "--format", "json"}, ExitIncompleteScan},
		{"min-coverage below the ratio exits 0", server.URL, []string{"scan", "--domain", "example.com", "--source", "certspotter", "--fail-on", "none", "--min-coverage", "10", "--format", "json"}, ExitOK},
		{"all sources unavailable beats strict", "http://127.0.0.1:1", []string{"scan", "--domain", "example.com", "--source", "certspotter", "--fail-on", "none", "--strict", "--format", "json"}, ExitSourceUnavailable},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := execute(context.Background(), test.args, &stdout, &stderr, scanDependencies(test.url, goldenProber()))
			if code != test.want {
				t.Fatalf("exit = %d, want %d; stderr=%s", code, test.want, stderr.String())
			}
		})
	}
	if code := execute(context.Background(), []string{"scan", "--domain", "example.com", "--fail-on", "bogus"}, &bytes.Buffer{}, &bytes.Buffer{}, scanDependencies(server.URL, goldenProber())); code != ExitUsageError {
		t.Fatalf("unknown fail-on kind exit = %d", code)
	}
	var stderr bytes.Buffer
	if code := execute(context.Background(), []string{"scan", "--domain", "example.com", "--format", "json", "--now", "not-a-time"}, &bytes.Buffer{}, &stderr, scanDependencies(server.URL, goldenProber())); code != ExitUsageError {
		t.Fatalf("bad --now exit = %d", code)
	}
}

func TestScanNowSetsGeneratedAt(t *testing.T) {
	server := certSpotterServer(t, ctOnlyFixture())
	var stdout, stderr bytes.Buffer
	code := execute(context.Background(), []string{"scan", "--domain", "example.com", "--source", "certspotter", "--format", "json", "--now", "2026-03-01T00:00:00Z"}, &stdout, &stderr, scanDependencies(server.URL, ctOnlyProber()))
	if code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"generated_at":"2026-03-01T00:00:00Z"`) {
		t.Fatalf("generated_at did not use --now: %s", stdout.String())
	}
}

func TestScanConfigFileAndPrecedence(t *testing.T) {
	server := certSpotterServer(t, ctOnlyFixture())
	directory := t.TempDir()
	path := filepath.Join(directory, "scadenza.yaml")
	if err := os.WriteFile(path, []byte("version: 1\ndomains: [example.com]\npolicy:\n  failOn: [none]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := execute(context.Background(), []string{"scan", "--config", path, "--source", "certspotter", "--format", "json"}, &stdout, &stderr, scanDependencies(server.URL, ctOnlyProber())); code != ExitOK {
		t.Fatalf("config-selected scenario exit = %d; stderr=%s", code, stderr.String())
	}
	// A command-line flag overrides the file value.
	if code := execute(context.Background(), []string{"scan", "--config", path, "--source", "certspotter", "--fail-on", "ct_only", "--format", "json"}, &bytes.Buffer{}, &bytes.Buffer{}, scanDependencies(server.URL, ctOnlyProber())); code != ExitFindingsPresent {
		t.Fatalf("flag must override file: exit = %d", code)
	}

	invalid := filepath.Join(directory, "bad.yaml")
	if err := os.WriteFile(invalid, []byte("version: 1\nunknownKey: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var badErr bytes.Buffer
	if code := execute(context.Background(), []string{"scan", "--config", invalid, "--domain", "example.com"}, &bytes.Buffer{}, &badErr, scanDependencies(server.URL, ctOnlyProber())); code != ExitUsageError || !strings.Contains(badErr.String(), "SCD-0022") {
		t.Fatalf("invalid config exit = %d stderr = %s", code, badErr.String())
	}
}
