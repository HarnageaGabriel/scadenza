package inventory

import (
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/tlsprobe"
	"github.com/google/go-cmp/cmp"
)

// TestVerdict100DIsComputedFromTheExactDuration pins the 100-day rule as
// documented in docs/cli/ct.md: verdict_100d is "ok" when the validity is at
// most 100*24h and "exceeds" only when it is strictly longer, and the
// exceeds-100d finding is reported for the latter only.
func TestVerdict100DIsComputedFromTheExactDuration(t *testing.T) {
	now := date(15, time.January)
	tests := []struct {
		name        string
		notAfter    time.Time
		wantVerdict string
		wantDays    int
		wantExceeds bool
	}{
		{
			name:        "exactly 100 days is ok",
			notAfter:    date(11, time.April),
			wantVerdict: "ok",
			wantDays:    100,
			wantExceeds: false,
		},
		{
			name:        "101 days exceeds",
			notAfter:    date(12, time.April),
			wantVerdict: "exceeds",
			wantDays:    101,
			wantExceeds: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			certificates, findings := Correlate(Input{
				Domains: []string{"example.com"},
				CT: []ct.Certificate{{
					Fingerprint: "aa", SubjectNames: []string{"example.com"}, Issuer: "CN=CA",
					NotBefore: date(1, time.January), NotAfter: test.notAfter, Source: "certspotter", DedupKey: "1",
				}},
				Live: []tlsprobe.Result{{
					Host: "example.com", Port: 443, Fingerprint: "aa", Names: []string{"example.com"},
					Issuer: "CN=CA", NotBefore: date(1, time.January), NotAfter: test.notAfter, Trusted: true,
				}},
				Now: now,
			})
			if len(certificates) != 1 {
				t.Fatalf("certificates = %+v", certificates)
			}
			certificate := certificates[0]
			if certificate.Verdict100D != test.wantVerdict {
				t.Errorf("verdict_100d = %q, want %q", certificate.Verdict100D, test.wantVerdict)
			}
			if certificate.LifetimeDays != test.wantDays {
				t.Errorf("lifetime_days = %d, want %d", certificate.LifetimeDays, test.wantDays)
			}
			found := false
			for _, finding := range findings {
				if finding.Kind == KindExceeds100D {
					found = true
				}
			}
			if found != test.wantExceeds {
				t.Errorf("exceeds-100d finding present = %v, want %v (findings = %+v)", found, test.wantExceeds, findings)
			}
		})
	}
}

// TestCorrelateMergesExpiryToTheEarliestSeen pins the expiry merge: one
// fingerprint seen with two different expiries is reported with the earliest
// expiry it was seen with, the tightest validity window, so no observation can
// stretch the lifetime the inventory reports.
//
// The same rule is applied in the Certificate Transparency, Key Vault, and
// Kubernetes merge paths, so the reported window is the tightest one seen and
// not a window that only exists because two sources disagreed.
func TestCorrelateMergesExpiryToTheEarliestSeen(t *testing.T) {
	notBefore := date(1, time.January)
	certificates, _ := Correlate(Input{
		Domains: []string{"example.com"},
		CT: []ct.Certificate{{
			Fingerprint: "aa", SubjectNames: []string{"example.com"}, Issuer: "CN=CA",
			NotBefore: notBefore, NotAfter: date(1, time.April), Source: "certspotter", DedupKey: "1",
		}},
		Live: []tlsprobe.Result{{
			Host: "example.com", Port: 443, Fingerprint: "aa", Names: []string{"example.com"},
			Issuer: "CN=CA", NotBefore: notBefore, NotAfter: date(1, time.May), Trusted: true,
		}},
		Now: date(15, time.January),
	})
	if len(certificates) != 1 {
		t.Fatalf("certificates = %+v", certificates)
	}
	certificate := certificates[0]
	if want := date(1, time.April); !certificate.NotAfter.Equal(want) {
		t.Errorf("not_after = %s, want the earliest expiry %s", certificate.NotAfter, want)
	}
	if want := 90; certificate.LifetimeDays != want {
		t.Errorf("lifetime_days = %d, want %d", certificate.LifetimeDays, want)
	}
}

// TestCorrelateKeepsOneObservationPerSource pins the observation promise: one
// certificate fingerprint reported by two Certificate Transparency sources is
// one certificate with one observation per source, so "one certificate, every
// place it appears" stays complete.
func TestCorrelateKeepsOneObservationPerSource(t *testing.T) {
	// The two records are the same certificate: same fingerprint and, on
	// purpose, the same dedup key, so only the source tells them apart.
	certificates, _ := Correlate(Input{
		Domains: []string{"example.com"},
		CT: []ct.Certificate{
			{
				Fingerprint: "aa", SubjectNames: []string{"example.com"}, Issuer: "CN=CA",
				NotBefore: date(1, time.January), NotAfter: date(1, time.April), Source: "certspotter", DedupKey: "same",
			},
			{
				Fingerprint: "aa", SubjectNames: []string{"example.com"}, Issuer: "CN=CA",
				NotBefore: date(1, time.January), NotAfter: date(1, time.April), Source: "crtsh", DedupKey: "same",
			},
		},
		Now: date(15, time.January),
	})
	if len(certificates) != 1 {
		t.Fatalf("certificates = %+v, want one certificate for one fingerprint", certificates)
	}
	observations := certificates[0].Observations
	if len(observations) != 2 {
		t.Fatalf("observations = %+v, want one per source", observations)
	}
	sources := []string{observations[0].Source, observations[1].Source}
	if diff := cmp.Diff([]string{SourceCertSpotter, SourceCrtSH}, sources); diff != "" {
		t.Errorf("observation sources (-want +got):\n%s", diff)
	}
	locations := []string{observations[0].Location, observations[1].Location}
	if diff := cmp.Diff([]string{"certspotter", "crtsh"}, locations); diff != "" {
		t.Errorf("observation locations (-want +got):\n%s", diff)
	}
}
