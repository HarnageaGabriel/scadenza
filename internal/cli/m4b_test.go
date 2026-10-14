package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/kube"
	"github.com/HarnageaGabriel/scadenza/internal/owner"
	"github.com/HarnageaGabriel/scadenza/internal/renewal"
)

// m4bScanDocument is the part of scadenza.scan/v1 that M4b adds: the
// per-certificate renewal classification and the per-owner workload summary.
type m4bScanDocument struct {
	Certificates []struct {
		Fingerprint string                 `json:"fingerprint_sha256"`
		Renewal     renewal.Classification `json:"renewal"`
	} `json:"certificates"`
	Owners []renewal.OwnerSummary `json:"owners"`
}

func decodeM4b(t *testing.T, output []byte) m4bScanDocument {
	t.Helper()
	var document m4bScanDocument
	if err := json.Unmarshal(output, &document); err != nil {
		t.Fatalf("decode scan output: %v\n%s", err, output)
	}
	return document
}

// TestScanKubeRenewalClassification is the M4b contract test: every certificate
// carries a renewal mode, health, evidence, and risks, and every certificate
// appears in the owners summary. ADR 0006 decisions 5 and 6.
func TestScanKubeRenewalClassification(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := execute([]string{"scan", "--kube", "--format", "json"}, &stdout, &stderr, scanKubeDependencies("x", fakeProber{}, fakeKubeSource{result: kubeFixture()}, nil)); code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
	}
	document := decodeM4b(t, stdout.Bytes())
	if len(document.Certificates) != 2 {
		t.Fatalf("certificates = %d, want 2", len(document.Certificates))
	}
	for _, certificate := range document.Certificates {
		if certificate.Renewal.Mode == "" || certificate.Renewal.Health == "" {
			t.Errorf("certificate %s has an empty renewal mode/health", certificate.Fingerprint)
		}
		if certificate.Renewal.Evidence == nil || certificate.Renewal.Risks == nil {
			t.Errorf("certificate %s has a null renewal array", certificate.Fingerprint)
		}
	}
	// The cert-manager Certificate for shop/web is automatic and healthy, the
	// unmanaged TLS Secret for payments/api-tls is unknown.
	for _, certificate := range document.Certificates {
		switch certificate.Fingerprint {
		case strings.Repeat("f", 64):
			if string(certificate.Renewal.Mode) != "automatic" || string(certificate.Renewal.Health) != "healthy" {
				t.Errorf("cert-manager certificate = %s/%s, want automatic/healthy", certificate.Renewal.Mode, certificate.Renewal.Health)
			}
		case strings.Repeat("e", 64):
			if string(certificate.Renewal.Mode) != "unknown" {
				t.Errorf("unmanaged secret mode = %s, want unknown", certificate.Renewal.Mode)
			}
			found := false
			for _, evidence := range certificate.Renewal.Evidence {
				if evidence.Fact == renewal.FactNoManagingController {
					found = true
				}
			}
			if !found {
				t.Errorf("unmanaged secret lacks no-managing-controller-found: %+v", certificate.Renewal.Evidence)
			}
		}
	}
	if len(document.Owners) != 2 {
		t.Fatalf("owners = %+v, want two buckets", document.Owners)
	}
	if document.Owners[0].Owner != "team-pay" || document.Owners[0].Unknown != 1 {
		t.Errorf("team-pay summary = %+v", document.Owners[0])
	}
	web := document.Owners[1]
	if web.Owner != "team-web" || web.Automatic != 1 || web.OwnerSource != string(owner.SourceMappingFile) {
		t.Errorf("team-web summary = %+v", web)
	}
}

// TestScanManualRenewalFromConfig checks the only positive evidence for manual
// renewal (ADR 0006 decision 5) and the manual workload columns (M4b).
func TestScanManualRenewalFromConfig(t *testing.T) {
	server := certSpotterServer(t, ctOnlyFixture())
	directory := t.TempDir()
	path := filepath.Join(directory, "scadenza.yaml")
	if err := os.WriteFile(path, []byte("version: 1\ndomains: [example.com]\nrenewal:\n  example.com: manual\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := execute([]string{"scan", "--config", path, "--source", "certspotter", "--format", "json"}, &stdout, &stderr, scanDependencies(server.URL, ctOnlyProber())); code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
	}
	document := decodeM4b(t, stdout.Bytes())
	for _, certificate := range document.Certificates {
		if certificate.Renewal.Mode != renewal.ModeManual {
			t.Errorf("mode = %s, want manual", certificate.Renewal.Mode)
		}
	}
	if len(document.Owners) != 1 || document.Owners[0].Owner != "(unowned)" {
		t.Fatalf("owners = %+v, want one unowned bucket", document.Owners)
	}
	unowned := document.Owners[0]
	if unowned.Manual != 2 || unowned.ManualRenewalsPerYear.Days200 != 4 || unowned.ManualRenewalsPerYear.Days100 != 8 || unowned.ManualRenewalsPerYear.Days47 != 16 {
		t.Errorf("unowned workload = %+v", unowned)
	}
}

// TestScanGroupByOnlyChangesTable checks --group-by groups the table rows and
// leaves JSON untouched.
func TestScanGroupByOnlyChangesTable(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := execute([]string{"scan", "--kube", "--format", "table", "--group-by", "owner"}, &stdout, &stderr, scanKubeDependencies("x", fakeProber{}, fakeKubeSource{result: kubeFixture()}, nil)); code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
	}
	table := stdout.String()
	for _, want := range []string{"GROUP owner: team-pay", "GROUP owner: team-web", "MODE", "HEALTH"} {
		if !strings.Contains(table, want) {
			t.Errorf("table missing %q:\n%s", want, table)
		}
	}

	var grouped, plain bytes.Buffer
	execute([]string{"scan", "--kube", "--format", "json", "--group-by", "names"}, &grouped, &bytes.Buffer{}, scanKubeDependencies("x", fakeProber{}, fakeKubeSource{result: kubeFixture()}, nil))
	execute([]string{"scan", "--kube", "--format", "json"}, &plain, &bytes.Buffer{}, scanKubeDependencies("x", fakeProber{}, fakeKubeSource{result: kubeFixture()}, nil))
	if grouped.String() != plain.String() {
		t.Errorf("--group-by changed JSON output")
	}
}

// TestScanRenewalRiskFindingFails checks the two renewal kinds that are on by
// default (ADR 0006 decision 6) block only when selected.
func TestScanRenewalRiskFindingFails(t *testing.T) {
	fixture := kubeFixture()
	fixture.Certificates[1].Observations[0].Kubernetes.Ready = "False"
	fixture.Certificates[1].Observations[0].Kubernetes.ReadyReason = "ACMEChallengeFailed"
	fixture.Certificates[1].Observations[0].Kubernetes.RenewalTime = "2026-01-01T00:00:00Z"

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"renewal-degraded fails by default", []string{"scan", "--kube", "--format", "json"}, ExitFindingsPresent},
		{"renewal-degraded can be excluded", []string{"scan", "--kube", "--format", "json", "--fail-on", "none"}, ExitOK},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := execute(test.args, &stdout, &stderr, scanKubeDependencies("x", fakeProber{}, fakeKubeSource{result: fixture}, nil)); code != test.want {
				t.Fatalf("exit = %d, want %d; stderr=%s", code, test.want, stderr.String())
			}
			if test.want == ExitFindingsPresent && !strings.Contains(stdout.String(), renewal.KindRenewalDegraded) {
				t.Fatalf("missing %s finding", renewal.KindRenewalDegraded)
			}
		})
	}
}

// TestScanRecoveredRenewalInputs is a small guard that the classification uses
// the injected clock, so the same input gives the same output.
func TestScanRecoveredRenewalInputs(t *testing.T) {
	dependencies := scanKubeDependencies("x", fakeProber{}, fakeKubeSource{result: kubeFixture()}, nil)
	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	dependencies.clock = fixedClock{Time: base}
	var first, second bytes.Buffer
	execute([]string{"scan", "--kube", "--format", "json"}, &first, &bytes.Buffer{}, dependencies)
	execute([]string{"scan", "--kube", "--format", "json"}, &second, &bytes.Buffer{}, dependencies)
	if first.String() != second.String() {
		t.Fatal("renewal classification is not deterministic")
	}
}

type fixedClock struct{ Time time.Time }

func (c fixedClock) Now() time.Time { return c.Time }

var _ = kube.IssuerTypeACME
