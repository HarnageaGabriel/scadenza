package renewal

import (
	"strings"
	"testing"
)

// TestRenewalGraceWindow pins the one-hour grace of the renewal deadline: a
// status.renewalTime that passed less than one hour before the evaluation
// instant is not overdue yet, and one that passed more than an hour ago is
// degraded.
//
// Promise: docs/renewal.md ("degraded - ... status.renewalTime passed more
// than one hour before the evaluation instant"). The same page defines
// healthy as "status.renewalTime and status.notAfter are in the future", so a
// renewal time in the past is never healthy; this test pins the grace window
// itself, which is the boundary the one-hour comparison draws.
func TestRenewalGraceWindow(t *testing.T) {
	const (
		now      = "2026-06-01T12:00:00Z"
		notAfter = "2026-09-01T00:00:00Z"
	)
	cases := []struct {
		name         string
		renewalTime  string
		wantDegraded bool
	}{
		{"renewal time 30 minutes in the past is inside the grace window", "2026-06-01T11:30:00Z", false},
		{"renewal time exactly one hour in the past is inside the grace window", "2026-06-01T11:00:00Z", false},
		{"renewal time one second more than an hour in the past is overdue", "2026-06-01T10:59:59Z", true},
		{"renewal time two hours in the past is overdue", "2026-06-01T10:00:00Z", true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			in := inputAt("2026-01-01T00:00:00Z", notAfter, now)
			in.Manager = &Manager{
				IssuerType:     "acme",
				Ready:          "True",
				RenewalTime:    test.renewalTime,
				StatusNotAfter: notAfter,
			}
			got := Classify(in)
			if degraded := got.Health == HealthDegraded; degraded != test.wantDegraded {
				t.Fatalf("health = %s, want degraded = %v (risks %v)", got.Health, test.wantDegraded, got.Risks)
			}
			_, ok := hasRisk(got, KindRenewalDegraded)
			if ok != test.wantDegraded {
				t.Fatalf("%s present = %v, want %v (risks %v)", KindRenewalDegraded, ok, test.wantDegraded, got.Risks)
			}
			if test.wantDegraded {
				risk, _ := hasRisk(got, KindRenewalDegraded)
				if !strings.Contains(risk.Detail, "passed more than one hour ago") {
					t.Fatalf("detail = %q, want the one-hour grace reason", risk.Detail)
				}
			}
		})
	}
}

// TestRenewalTimeInTheFutureIsHealthy pins the documented healthy verdict: a
// Certificate with Ready=True whose status.renewalTime and status.notAfter
// are both in the future is healthy.
//
// Promise: docs/renewal.md ("healthy - a controller reports Ready=True and
// both status.renewalTime and status.notAfter are in the future").
func TestRenewalTimeInTheFutureIsHealthy(t *testing.T) {
	in := inputAt("2026-01-01T00:00:00Z", "2026-09-01T00:00:00Z", "2026-06-01T12:00:00Z")
	in.Manager = &Manager{
		IssuerType:     "acme",
		Ready:          "True",
		RenewalTime:    "2026-08-01T00:00:00Z",
		StatusNotAfter: "2026-09-01T00:00:00Z",
	}
	got := Classify(in)
	if got.Health != HealthHealthy {
		t.Fatalf("health = %s, want healthy (evidence %v)", got.Health, got.Evidence)
	}
}

// TestRenewBeforeAgainstIssuedLifetime pins the inclusive boundary of the
// renew-before-exceeds-lifetime finding: a fixed spec.renewBefore equal to the
// issued lifetime renews in a loop now, one hour shorter does not.
//
// Promise: docs/renewal.md ("renew-before-exceeds-lifetime - a fixed
// spec.renewBefore is at or beyond the actual issued lifetime, so cert-manager
// renews in a loop now").
func TestRenewBeforeAgainstIssuedLifetime(t *testing.T) {
	cases := []struct {
		name        string
		renewBefore string
		wantRisk    bool
	}{
		{"renewBefore equal to the issued lifetime renews in a loop", "2160h0m0s", true},
		{"renewBefore one hour shorter than the issued lifetime does not loop", "2159h0m0s", false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			// The issued lifetime is 2160h: 2026-01-01 to 2026-04-01 is 90 days.
			in := inputAt("2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "2026-02-01T00:00:00Z")
			in.Manager = &Manager{IssuerType: "acme", RenewBefore: test.renewBefore}
			got := Classify(in)
			risk, ok := hasRisk(got, KindRenewBeforeExceedsLifetime)
			if ok != test.wantRisk {
				t.Fatalf("%s present = %v, want %v (risks %v)", KindRenewBeforeExceedsLifetime, ok, test.wantRisk, got.Risks)
			}
			if ok && !strings.Contains(risk.Detail, "2160h0m0s") {
				t.Fatalf("detail = %q, want the issued lifetime 2160h0m0s", risk.Detail)
			}
		})
	}
}

// TestKeyVaultRenewTriggerAtLowerBound pins the inclusive boundary of the
// keyvault-renew-trigger-exceeds-lifetime finding: an AutoRenew action that
// triggers exactly one conservative month (28 days) before the expiry of a
// one-month policy is already at the lifetime, one day earlier is not.
//
// Promise: docs/renewal.md ("keyvault-renew-trigger-exceeds-lifetime") and the
// conservative 28-day lower bound of one calendar month used for a Key Vault
// policy lifetime.
func TestKeyVaultRenewTriggerAtLowerBound(t *testing.T) {
	months := 1
	cases := []struct {
		name             string
		daysBeforeExpiry int
		wantRisk         bool
	}{
		{"AutoRenew 28 days before expiry is the one-month lower bound", 28, true},
		{"AutoRenew 27 days before expiry is inside the lifetime", 27, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			days := test.daysBeforeExpiry
			in := inputAt("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z", "2026-06-01T00:00:00Z")
			in.KeyVault = &KeyVault{
				Issuer:          "DigiCert",
				ValidityMonths:  &months,
				LifetimeActions: []LifetimeAction{{Type: "AutoRenew", DaysBeforeExpiry: &days}},
			}
			got := Classify(in)
			risk, ok := hasRisk(got, KindKeyVaultRenewTriggerExceedsLifetime)
			if ok != test.wantRisk {
				t.Fatalf("%s present = %v, want %v (risks %v)", KindKeyVaultRenewTriggerExceedsLifetime, ok, test.wantRisk, got.Risks)
			}
			if ok {
				if !strings.Contains(risk.Detail, "28-day lower bound") {
					t.Fatalf("detail = %q, want the 28-day lower bound", risk.Detail)
				}
				if !strings.Contains(risk.Detail, "28 days before expiry") {
					t.Fatalf("detail = %q, want the 28-day trigger", risk.Detail)
				}
			}
		})
	}
}

// TestDefaultDurationNamesNinetyDays pins the documented cert-manager default
// used when spec.duration is absent: the evidence fact duration-source is
// "default" and the finding detail names the 90-day default.
//
// Promise: docs/renewal.md ("When spec.duration is absent, cert-manager's
// documented 90-day default is used and recorded as the evidence fact
// duration-source=default") and https://cert-manager.io/docs/usage/certificate/
// (spec.duration defaults to 90 days).
func TestDefaultDurationNamesNinetyDays(t *testing.T) {
	in := inputAt("2028-01-01T00:00:00Z", "2028-04-01T00:00:00Z", "2028-01-02T00:00:00Z")
	in.Manager = &Manager{IssuerType: "acme", ACMEServer: "https://acme-v02.api.letsencrypt.org/directory"}
	got := Classify(in)
	if !hasEvidence(got, SourceCertManager, FactDurationSource, "default") {
		t.Fatalf("missing %s=default: %v", FactDurationSource, got.Evidence)
	}
	risk, ok := hasRisk(got, KindDurationExceedsNextLimit)
	if !ok {
		t.Fatalf("missing %s for the default duration: %v", KindDurationExceedsNextLimit, got.Risks)
	}
	if !strings.Contains(risk.Detail, "cert-manager default 90 days") {
		t.Fatalf("detail = %q, want the documented 90-day default", risk.Detail)
	}
}

// TestKeyVaultValidityUpperBound pins the conservative 31-day month used for
// a Key Vault policy validity: three months is at most 93 days and fits the
// 100-day limit that governs the next issuance, four months is 124 days and
// does not.
//
// Promise: docs/renewal.md ("keyvault-validity-exceeds-lifetime") with the
// conservative upper bound of 31 days per calendar month.
func TestKeyVaultValidityUpperBound(t *testing.T) {
	months := 3
	base := Input{
		NotBefore: at("2026-01-01T00:00:00Z"),
		Now:       at("2026-06-01T00:00:00Z"),
		KeyVault:  &KeyVault{Issuer: "DigiCert", ValidityMonths: &months},
	}
	if _, ok := hasRisk(Classify(base), KindKeyVaultValidityExceedsNextLimit); ok {
		t.Fatal("three months (93 days) must fit the 100-day next limit")
	}
	months = 4
	risk, ok := hasRisk(Classify(base), KindKeyVaultValidityExceedsNextLimit)
	if !ok {
		t.Fatal("four months (124 days) must exceed the 100-day next limit")
	}
	if !strings.Contains(risk.Detail, "124 days") {
		t.Fatalf("detail = %q, want the 124-day conservative upper bound", risk.Detail)
	}
}

// TestLetsEncryptNextStepAtExactInstant pins the step selection at the exact
// instant a Let's Encrypt lifetime takes effect: the step that has just taken
// effect is the one in force, so the next step is the following one.
//
// Promise: https://letsencrypt.org/2025/12/02/from-90-to-45 (the 64-day step
// takes effect on 2027-02-10 and the 45-day step on 2028-02-16).
func TestLetsEncryptNextStepAtExactInstant(t *testing.T) {
	const directory = "https://acme-v02.api.letsencrypt.org/directory"
	cases := []struct {
		name          string
		now           string
		wantEffective string
		wantDays      int
		wantDaysText  string
	}{
		{
			name:          "one second before the 64-day step the 64-day step is next",
			now:           "2027-02-09T23:59:59Z",
			wantEffective: "2027-02-10T00:00:00Z",
			wantDays:      64,
			wantDaysText:  "64 days",
		},
		{
			name:          "exactly at the 64-day step the 45-day step is next",
			now:           "2027-02-10T00:00:00Z",
			wantEffective: "2028-02-16T00:00:00Z",
			wantDays:      45,
			wantDaysText:  "45 days",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			effective, days, ok := letsEncryptNextStep(directory, at(test.now))
			if !ok || effective != test.wantEffective || days != test.wantDays {
				t.Fatalf("next step at %s = %q %d %v, want %q %d true",
					test.now, effective, days, ok, test.wantEffective, test.wantDays)
			}

			// The same boundary is visible in the finding an issuer on the
			// Let's Encrypt directory gets for a renewBefore that reaches the
			// next announced lifetime.
			in := inputAt("2026-06-01T00:00:00Z", "2027-06-01T00:00:00Z", test.now)
			in.Manager = &Manager{IssuerType: "acme", ACMEServer: directory, RenewBefore: "1536h0m0s"}
			risk, ok := hasRisk(Classify(in), KindRenewBeforeLoopAtNextLimit)
			if !ok {
				t.Fatalf("missing %s at %s", KindRenewBeforeLoopAtNextLimit, test.now)
			}
			if risk.Effective != test.wantEffective {
				t.Fatalf("effective = %q, want %q", risk.Effective, test.wantEffective)
			}
			if !strings.Contains(risk.Detail, test.wantDaysText) {
				t.Fatalf("detail = %q, want the %s lifetime", risk.Detail, test.wantDaysText)
			}
		})
	}
}
