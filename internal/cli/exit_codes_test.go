package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/inventory"
	"github.com/HarnageaGabriel/scadenza/internal/kube"
	"github.com/HarnageaGabriel/scadenza/internal/tlsprobe"
)

// scanSource returns a scripted Certificate Transparency source. An
// unavailable source fails every query, which is what "every requested
// external source failed" looks like to the scan.
func scanSource(available bool) ct.Source {
	if !available {
		return &fakeCTSource{name: "certspotter", err: errors.New("the Certificate Transparency source is unreachable")}
	}
	return &fakeCTSource{name: "certspotter", certificates: []ct.Certificate{ctRecord("example.com")}}
}

// liveOnlyProber presents a certificate that no Certificate Transparency
// source reported, so the scan reports the blocking live_only finding.
func liveOnlyProber() fakeProber {
	return fakeProber{results: map[string]tlsprobe.Result{
		"example.com:443": {
			Fingerprint: strings.Repeat("b", 64),
			Serial:      "0b",
			Names:       []string{"example.com"},
			Issuer:      "CN=Example Root",
			NotBefore:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:    time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
			Trusted:     true,
		},
	}}
}

// matchedProber presents exactly the certificate the scripted Certificate
// Transparency source reported, so the scan correlates it as matched and
// reports no finding that could block.
func matchedProber() fakeProber {
	return fakeProber{results: map[string]tlsprobe.Result{
		"example.com:443": {
			Fingerprint: strings.Repeat("a", 64),
			Serial:      "0a",
			Names:       []string{"example.com"},
			Issuer:      "CN=Example Root",
			NotBefore:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:    time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
			Trusted:     true,
		},
	}}
}

// scanDependenciesWithFailedKube wires a scripted Certificate Transparency
// source and a prober into the scan, with a Kubernetes source that cannot be
// loaded, so the coverage reports the kube source as failed.
func scanDependenciesWithFailedKube(source ct.Source, prober hostProber) ctDependencies {
	dependencies := wiringDependencies(source, prober)
	dependencies.loadKube = func(kube.LoadOptions, kube.Options) (kube.Source, error) {
		return nil, errors.New("the Kubernetes cluster is unreachable")
	}
	return dependencies
}

// TestScanSourceUnavailableBeatsBlockingFinding proves the documented
// precedence: when every requested external source was unavailable, the scan
// exits 4 and never 3, even when the live handshake presents a certificate
// that is not in Certificate Transparency and is therefore a blocking
// live_only finding.
func TestScanSourceUnavailableBeatsBlockingFinding(t *testing.T) {
	t.Run("an unavailable source beats a blocking finding", func(t *testing.T) {
		dependencies := wiringDependencies(scanSource(false), liveOnlyProber())
		var stdout, stderr bytes.Buffer
		code := execute(context.Background(), []string{"scan", "--domain", "example.com", "--source", "certspotter", "--format", "json"},
			&stdout, &stderr, dependencies)
		if code != ExitSourceUnavailable {
			t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitSourceUnavailable, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), `"kind":"live_only"`) {
			t.Fatalf("the run did not report the blocking finding: %s", stdout.String())
		}
	})

	// The same finding with an available source exits 3, so the exit 4 above
	// is the precedence and not a missing finding.
	t.Run("the same finding alone exits 3", func(t *testing.T) {
		dependencies := wiringDependencies(scanSource(true), liveOnlyProber())
		var stdout, stderr bytes.Buffer
		code := execute(context.Background(), []string{"scan", "--domain", "example.com", "--source", "certspotter", "--format", "json"},
			&stdout, &stderr, dependencies)
		if code != ExitFindingsPresent {
			t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitFindingsPresent, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), `"kind":"live_only"`) {
			t.Fatalf("the run did not report the blocking finding: %s", stdout.String())
		}
	})
}

// TestScanStrictTreatsFailedSourceAsIncomplete proves that --strict reports a
// source whose coverage status is failed as an incomplete scan (exit 5), and
// that the same run without --strict is not an incomplete scan.
func TestScanStrictTreatsFailedSourceAsIncomplete(t *testing.T) {
	dependencies := scanDependenciesWithFailedKube(scanSource(true), matchedProber())
	var stdout, stderr bytes.Buffer
	code := execute(context.Background(), []string{"scan", "--domain", "example.com", "--source", "certspotter", "--kube", "--strict", "--format", "json"},
		&stdout, &stderr, dependencies)
	if code != ExitIncompleteScan {
		t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitIncompleteScan, stdout.String(), stderr.String())
	}
	coverage := sourceCoverage(stdout.Bytes())
	if coverage["kube"].Status != inventory.SourceStatusFailed {
		t.Fatalf("kube coverage = %+v, want status %s", coverage["kube"], inventory.SourceStatusFailed)
	}
	// The Kubernetes source is the only gap: every other source answered, so
	// the failed source is what makes the scan incomplete.
	if coverage["certspotter"].Status != inventory.SourceStatusOK {
		t.Fatalf("certspotter coverage = %+v, want status %s", coverage["certspotter"], inventory.SourceStatusOK)
	}
	if coverage["tls"].Status != inventory.SourceStatusOK {
		t.Fatalf("tls coverage = %+v, want status %s", coverage["tls"], inventory.SourceStatusOK)
	}
	if !strings.Contains(stderr.String(), "SCD-0020") {
		t.Fatalf("missing SCD-0020: %s", stderr.String())
	}

	// Without --strict a failed source is only reported, so the run is not an
	// incomplete scan and the exit code is not 5.
	stdout.Reset()
	stderr.Reset()
	code = execute(context.Background(), []string{"scan", "--domain", "example.com", "--source", "certspotter", "--kube", "--format", "json"},
		&stdout, &stderr, dependencies)
	if code != ExitOK {
		t.Fatalf("exit without --strict = %d, want %d; stdout=%s stderr=%s", code, ExitOK, stdout.String(), stderr.String())
	}
}

// TestScanExitPrecedenceCombinations proves the documented precedence
// 2 (usage) > 4 (source unavailable) > 3 (blocking finding) > 5 (incomplete
// scan) > 0 for every combination of a usage problem, an unavailable source, a
// blocking finding and an incomplete scan that TestScanExitPrecedence does
// not already cover.
func TestScanExitPrecedenceCombinations(t *testing.T) {
	cases := []struct {
		name        string
		usage       bool
		unavailable bool
		blocking    bool
		incomplete  bool
		want        int
	}{
		{name: "usage beats an unavailable source", usage: true, unavailable: true, want: ExitUsageError},
		{name: "usage beats a blocking finding", usage: true, blocking: true, want: ExitUsageError},
		{name: "usage beats an incomplete scan", usage: true, incomplete: true, want: ExitUsageError},
		{name: "an unavailable source beats a blocking finding", unavailable: true, blocking: true, want: ExitSourceUnavailable},
		{name: "usage beats an unavailable source and a blocking finding", usage: true, unavailable: true, blocking: true, want: ExitUsageError},
		{name: "usage beats an unavailable source and an incomplete scan", usage: true, unavailable: true, incomplete: true, want: ExitUsageError},
		{name: "usage beats a blocking finding and an incomplete scan", usage: true, blocking: true, incomplete: true, want: ExitUsageError},
		{name: "an unavailable source beats a blocking finding and an incomplete scan", unavailable: true, blocking: true, incomplete: true, want: ExitSourceUnavailable},
		{name: "usage beats every other condition", usage: true, unavailable: true, blocking: true, incomplete: true, want: ExitUsageError},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			format := "json"
			if test.usage {
				format = "xml"
			}
			args := []string{"scan", "--domain", "example.com", "--source", "certspotter", "--kube", "--format", format}
			if !test.blocking {
				args = append(args, "--fail-on", "none")
			}
			if test.incomplete {
				args = append(args, "--strict")
			}
			dependencies := scanDependenciesWithFailedKube(scanSource(!test.unavailable), liveOnlyProber())
			var stdout, stderr bytes.Buffer
			code := execute(context.Background(), args, &stdout, &stderr, dependencies)
			if code != test.want {
				t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, test.want, stdout.String(), stderr.String())
			}
			if test.usage {
				// A usage problem is detected before any scan work, so no
				// result is reported and the other conditions of the case are
				// never reached.
				if !strings.Contains(stderr.String(), "SCD-0001") {
					t.Errorf("missing usage diagnostic: %s", stderr.String())
				}
				if stdout.Len() != 0 {
					t.Errorf("a bad invocation reported a result: %s", stdout.String())
				}
				return
			}
			if test.unavailable && !strings.Contains(stderr.String(), "SCD-0002") {
				t.Errorf("missing source failure diagnostic: %s", stderr.String())
			}
			if test.blocking && !strings.Contains(stdout.String(), `"kind":"live_only"`) {
				t.Errorf("missing blocking finding: %s", stdout.String())
			}
			if test.incomplete && !strings.Contains(stderr.String(), "SCD-0020") {
				t.Errorf("missing incomplete diagnostic: %s", stderr.String())
			}
		})
	}
}
