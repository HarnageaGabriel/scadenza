package renewal

import (
	"fmt"
	"strings"
	"testing"
)

// TestRenewalConfigInvalid exercises cert-manager's own spec constraints (M4b
// review finding 2): a value the official rules reject is reported as the
// distinct renewal-config-invalid risk instead of being folded into a lifetime
// risk, and it is never a default --fail-on kind.
//
// Source: https://cert-manager.io/docs/usage/certificate/
func TestRenewalConfigInvalid(t *testing.T) {
	cases := []struct {
		name    string
		manager *Manager
		// notBefore, notAfter, and now override the default valid certificate.
		notBefore string
		notAfter  string
		now       string
	}{
		{
			name:    "duration equal to renewBefore is rejected",
			manager: &Manager{IssuerType: "acme", Duration: "720h0m0s", RenewBefore: "720h0m0s"},
		},
		{
			name:    "duration below the one hour minimum",
			manager: &Manager{IssuerType: "acme", Duration: "30m0s"},
		},
		{
			name:    "renewBefore below the five minute minimum",
			manager: &Manager{IssuerType: "acme", RenewBefore: "60s"},
		},
		{
			name:    "renewBefore greater than duration",
			manager: &Manager{IssuerType: "acme", Duration: "720h0m0s", RenewBefore: "1200h0m0s"},
		},
		{
			name:    "unparsable duration",
			manager: &Manager{IssuerType: "acme", Duration: "ninety days"},
		},
		{
			name:    "renewBeforePercentage outside one to ninety nine",
			manager: &Manager{IssuerType: "acme", RenewBeforePercentage: "150"},
		},
		{
			name:      "renewBeforePercentage of the actual issued lifetime below five minutes",
			manager:   &Manager{IssuerType: "acme", Duration: "8760h0m0s", RenewBeforePercentage: "5"},
			notBefore: "2026-01-01T00:00:00Z", notAfter: "2026-01-01T01:00:00Z", now: "2026-01-01T00:30:00Z",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			notBefore, notAfter, now := "2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "2026-02-01T00:00:00Z"
			if test.notBefore != "" {
				notBefore, notAfter, now = test.notBefore, test.notAfter, test.now
			}
			in := inputAt(notBefore, notAfter, now)
			in.Manager = test.manager
			got := Classify(in)
			if _, ok := hasRisk(got, KindRenewalConfigInvalid); !ok {
				t.Fatalf("missing %s risk: %v", KindRenewalConfigInvalid, got.Risks)
			}
		})
	}
}

// TestRenewBeforePercentageUsesIssuedLifetime pins that a percentage is a
// percentage of the actual issued lifetime: a valid percentage is accepted and
// adapts to a shorter lifetime instead of looping.
func TestRenewBeforePercentageUsesIssuedLifetime(t *testing.T) {
	in := inputAt("2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "2026-02-01T00:00:00Z")
	in.Manager = &Manager{IssuerType: "acme", Duration: "2160h0m0s", RenewBeforePercentage: "50"}
	got := Classify(in)
	if _, ok := hasRisk(got, KindRenewalConfigInvalid); ok {
		t.Fatalf("valid percentage reported invalid: %v", got.Risks)
	}
	if _, ok := hasRisk(got, KindRenewBeforeExceedsLifetime); ok {
		t.Fatalf("percentage must not loop: %v", got.Risks)
	}
}

// TestDurationDefaultNinetyDays pins M4b review finding 3: an absent
// spec.duration is the documented 90-day default for the duration check, and
// the default is recorded as evidence.
func TestDurationDefaultNinetyDays(t *testing.T) {
	in := inputAt("2028-01-01T00:00:00Z", "2028-04-01T00:00:00Z", "2028-01-02T00:00:00Z")
	in.Manager = &Manager{IssuerType: "acme", ACMEServer: "https://acme-v02.api.letsencrypt.org/directory"}
	got := Classify(in)
	risk, ok := hasRisk(got, KindDurationExceedsNextLimit)
	if !ok {
		t.Fatalf("missing %s for the default 90 days: %v", KindDurationExceedsNextLimit, got.Risks)
	}
	if risk.Effective != "2029-03-15T00:00:00Z" {
		t.Fatalf("effective = %q, want the 47 day step", risk.Effective)
	}
	if !hasEvidence(got, SourceCertManager, FactDurationSource, "default") {
		t.Fatalf("missing %s=default: %v", FactDurationSource, got.Evidence)
	}
}

// TestRenewalRisksUseEvaluationInstant pins M4b review finding 4: the current
// and next CA/B step are chosen from --now, not from the policy computed from
// the certificate notBefore.
func TestRenewalRisksUseEvaluationInstant(t *testing.T) {
	// now is after the 2026-03-15 step, so the next step is 2027-03-15, even
	// though the certificate was issued on 2026-01-01.
	in := inputAt("2026-01-01T00:00:00Z", "2026-09-08T00:00:00Z", "2026-06-01T00:00:00Z")
	in.Manager = &Manager{IssuerType: "acme", RenewBefore: "2400h0m0s"}
	got := Classify(in)
	risk, ok := hasRisk(got, KindRenewBeforeLoopAtNextLimit)
	if !ok || risk.Effective != "2027-03-15T00:00:00Z" {
		t.Fatalf("next-limit risk = %+v ok=%v, want effective 2027-03-15", risk, ok)
	}

	in = inputAt("2026-01-01T00:00:00Z", "2027-06-01T00:00:00Z", "2026-06-01T00:00:00Z")
	in.DeclaredMode = ModeManual
	got = Classify(in)
	manual, ok := hasRisk(got, KindManualRenewalAfterLimit)
	if !ok || manual.Effective != "2027-03-15T00:00:00Z" {
		t.Fatalf("manual risk = %+v ok=%v, want effective 2027-03-15", manual, ok)
	}

	// With no further scheduled step the limit in force at now applies.
	in = inputAt("2029-06-01T00:00:00Z", "2029-09-01T00:00:00Z", "2029-06-02T00:00:00Z")
	in.Manager = &Manager{IssuerType: "acme", ACMEServer: "https://acme-v02.api.letsencrypt.org/directory", Duration: "2160h0m0s"}
	got = Classify(in)
	current, ok := hasRisk(got, KindDurationExceedsNextLimit)
	if !ok || current.Effective != "" {
		t.Fatalf("current-limit risk = %+v ok=%v, want no effective date", current, ok)
	}
}

// TestCadenceWindowIsFixed365Days pins M4b review finding 5: the window is a
// fixed 365*24h bounded by [now-365d, now], so a leap-year window cannot span
// 366 days and a record issued after the evaluation instant is ignored.
func TestCadenceWindowIsFixed365Days(t *testing.T) {
	in := inputAt("2027-01-01T00:00:00Z", "2027-06-01T00:00:00Z", "2028-03-01T00:00:00Z")
	in.Names = []string{"example.com"}
	within := Issuance{Names: []string{"example.com"}, NotBefore: at("2027-03-02T00:00:00Z")}  // exactly 365 days before now
	outside := Issuance{Names: []string{"example.com"}, NotBefore: at("2027-03-01T12:00:00Z")} // 365.5 days before now
	in.CT = []Issuance{within, outside}
	got := Classify(in)
	if !hasEvidence(got, SourceCT, FactCTIssuances365d, "1") {
		t.Fatalf("ct-issuances-365d = %v, want 1", got.Evidence)
	}

	future := Issuance{Names: []string{"example.com"}, NotBefore: at("2028-06-01T00:00:00Z")}
	in.CT = []Issuance{within, outside, future}
	ignored := Classify(in)
	if fmt.Sprint(ignored.Evidence) != fmt.Sprint(got.Evidence) {
		t.Fatalf("a future record changed the evidence: %v vs %v", ignored.Evidence, got.Evidence)
	}
}

// TestCadenceDeduplicatesIssuanceIdentity pins M4b review finding 6: cadence
// counts one issuance once, however many CT records describe it.
func TestCadenceDeduplicatesIssuanceIdentity(t *testing.T) {
	in := inputAt("2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "2026-02-01T00:00:00Z")
	in.Names = []string{"example.com"}
	in.CT = []Issuance{
		// The same record returned by two overlapping domain queries.
		{Names: []string{"example.com"}, NotBefore: at("2025-10-01T00:00:00Z"), Issuer: "CN=CA", Serial: "1a", Fingerprint: strings.Repeat("a", 64)},
		{Names: []string{"example.com", "www.example.com"}, NotBefore: at("2025-10-01T00:00:00Z"), Issuer: "CN=CA", Serial: "1a", Fingerprint: strings.Repeat("a", 64)},
		// The precertificate and the final certificate share issuer and serial.
		{Names: []string{"example.com"}, NotBefore: at("2025-07-01T00:00:00Z"), Issuer: "CN=CA", Serial: "2b", Fingerprint: strings.Repeat("b", 64)},
		{Names: []string{"example.com"}, NotBefore: at("2025-07-01T00:00:00Z"), Issuer: "CN=CA", Serial: "2b", Fingerprint: strings.Repeat("c", 64)},
		// A distinct issuance still counts.
		{Names: []string{"example.com"}, NotBefore: at("2025-04-01T00:00:00Z"), Issuer: "CN=CA", Serial: "3c", Fingerprint: strings.Repeat("d", 64)},
	}
	got := Classify(in)
	if !hasEvidence(got, SourceCT, FactCTIssuances365d, "3") {
		t.Fatalf("ct-issuances-365d = %v, want 3", got.Evidence)
	}
}

// TestLetsEncryptStepLabeledAnnounced pins M4b review finding 8: the announced
// Let's Encrypt lifetimes are not presented as confirmed while the VERIFY
// marker on their dates stands.
func TestLetsEncryptStepLabeledAnnounced(t *testing.T) {
	in := inputAt("2026-06-01T00:00:00Z", "2026-08-30T00:00:00Z", "2026-06-02T00:00:00Z")
	in.Manager = &Manager{IssuerType: "acme", ACMEServer: "https://acme-v02.api.letsencrypt.org/directory", RenewBefore: "1680h0m0s"}
	got := Classify(in)
	risk, ok := hasRisk(got, KindRenewBeforeLoopAtNextLimit)
	if !ok {
		t.Fatalf("missing the Let's Encrypt risk: %v", got.Risks)
	}
	if !strings.Contains(risk.Detail, "announced, not confirmed") {
		t.Fatalf("detail = %q, want an announced-not-confirmed label", risk.Detail)
	}
}
