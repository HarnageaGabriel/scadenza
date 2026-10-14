package renewal

import (
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/policy"
)

func at(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(err)
	}
	return parsed
}

// inputAt builds an Input for a certificate valid from notBefore to notAfter
// with the M4a policy assessment already computed.
func inputAt(notBefore, notAfter string, now string) Input {
	start, end := at(notBefore), at(notAfter)
	return Input{
		Names:     []string{"example.com"},
		NotBefore: start,
		NotAfter:  end,
		Policy:    policy.Assess(start, end),
		Now:       at(now),
	}
}

func hasEvidence(classification Classification, source, fact, value string) bool {
	for _, item := range classification.Evidence {
		if item.Source == source && item.Fact == fact && item.Value == value {
			return true
		}
	}
	return false
}

func hasRisk(classification Classification, kind string) (Risk, bool) {
	for _, risk := range classification.Risks {
		if risk.Kind == kind {
			return risk, true
		}
	}
	return Risk{}, false
}

// TestClassifyModeAndHealth is a table test. Each case cites the documented
// source of the rule it exercises.
func TestClassifyModeAndHealth(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(*Input)
		wantMode   Mode
		wantHealth Health
		wantRisk   string
		source     string
	}{
		{
			name: "cert-manager auto-renew health is a baseline",
			// Source: https://cert-manager.io/docs/usage/certificate/ (status.renewalTime is when renewal is attempted; Ready condition)
			mutate: func(in *Input) {
				in.Manager = &Manager{IssuerType: "acme", ACMEServer: "https://acme-v02.api.letsencrypt.org/directory", Ready: "True", RenewalTime: "2026-03-01T00:00:00Z", StatusNotAfter: "2026-04-01T00:00:00Z"}
			},
			wantMode:   ModeAutomatic,
			wantHealth: HealthHealthy,
		},
		{
			name:       "Readable cert-manager facts alone are configured, no signal yet",
			mutate:     func(in *Input) { in.Manager = &Manager{IssuerType: "acme"} },
			wantMode:   ModeAutomatic,
			wantHealth: HealthConfigured,
		},
		{
			name: "Ready=False is degraded",
			mutate: func(in *Input) {
				in.Manager = &Manager{IssuerType: "acme", Ready: "False", ReadyReason: "ACMEChallengeFailed"}
			},
			wantMode:   ModeAutomatic,
			wantHealth: HealthDegraded,
			wantRisk:   KindRenewalDegraded,
		},
		{
			name: "renewalTime overdue by more than an hour is degraded",
			mutate: func(in *Input) {
				in.Manager = &Manager{IssuerType: "acme", Ready: "True", RenewalTime: "2026-01-31T00:00:00Z", StatusNotAfter: "2026-04-01T00:00:00Z"}
			},
			wantMode:   ModeAutomatic,
			wantHealth: HealthDegraded,
			wantRisk:   KindRenewalDegraded,
		},
		{
			name: "status.notAfter passed is degraded",
			mutate: func(in *Input) {
				in.Manager = &Manager{IssuerType: "acme", Ready: "True", StatusNotAfter: "2026-01-15T00:00:00Z"}
			},
			wantMode:   ModeAutomatic,
			wantHealth: HealthDegraded,
			wantRisk:   KindRenewalDegraded,
		},
		{
			name: "external issuer still renews automatically but health is capped",
			mutate: func(in *Input) {
				in.Manager = &Manager{IssuerType: "external", Ready: "True", RenewalTime: "2026-03-01T00:00:00Z", StatusNotAfter: "2026-04-01T00:00:00Z"}
			},
			wantMode:   ModeAutomatic,
			wantHealth: HealthConfigured,
		},
		{
			name:       "annotated TLS secret is automatic and configured",
			mutate:     func(in *Input) { in.HasKube = true; in.Secrets = []Secret{{CertificateName: "shop-web"}} },
			wantMode:   ModeAutomatic,
			wantHealth: HealthConfigured,
		},
		{
			name:       "unmanaged TLS secret is unknown, never manual",
			mutate:     func(in *Input) { in.HasKube = true; in.Secrets = []Secret{{}} },
			wantMode:   ModeUnknown,
			wantHealth: HealthUnknown,
		},
		{
			name:       "CT-only is unknown, never manual",
			mutate:     func(in *Input) { in.HasCT = true },
			wantMode:   ModeUnknown,
			wantHealth: HealthUnknown,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			in := inputAt("2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "2026-02-01T00:00:00Z")
			test.mutate(&in)
			got := Classify(in)
			if got.Mode != test.wantMode || got.Health != test.wantHealth {
				t.Fatalf("mode/health = %s/%s, want %s/%s (evidence %v)", got.Mode, got.Health, test.wantMode, test.wantHealth, got.Evidence)
			}
			if test.wantRisk != "" {
				if _, ok := hasRisk(got, test.wantRisk); !ok {
					t.Fatalf("missing risk %s in %v", test.wantRisk, got.Risks)
				}
			}
		})
	}
}

// TestClassifyNeverInfersWithoutEvidence pins the ADR 0006 decision 5 rule:
// missing evidence is unknown, with the fact that proves why.
func TestClassifyNeverInfersWithoutEvidence(t *testing.T) {
	in := inputAt("2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "2026-02-01T00:00:00Z")
	in.HasCT, in.HasLive = true, true
	got := Classify(in)
	if got.Mode != ModeUnknown {
		t.Fatalf("mode = %s, want unknown", got.Mode)
	}
	if !hasEvidence(got, SourceCT, FactNoManagingController, "true") {
		t.Fatalf("missing no-managing-controller-found evidence: %v", got.Evidence)
	}

	secret := inputAt("2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "2026-02-01T00:00:00Z")
	secret.HasKube = true
	secret.Secrets = []Secret{{}}
	got = Classify(secret)
	if got.Mode != ModeUnknown || !hasEvidence(got, SourceKubeSecret, FactNoManagingController, "true") {
		t.Fatalf("unmanaged secret = %+v", got)
	}
}

// TestClassifyManualRequiresDeclaration pins the only positive evidence for
// manual renewal (ADR 0006 decision 5): a scadenza.yaml declaration, and later
// Key Vault EmailContacts-only policies (M5).
func TestClassifyManualRequiresDeclaration(t *testing.T) {
	in := inputAt("2026-06-01T00:00:00Z", "2027-06-01T00:00:00Z", "2026-07-01T00:00:00Z")
	in.DeclaredMode = ModeManual
	got := Classify(in)
	if got.Mode != ModeManual || got.Health != HealthUnknown {
		t.Fatalf("mode/health = %s/%s, want manual/unknown", got.Mode, got.Health)
	}
	if !hasEvidence(got, SourceConfig, FactRenewalModeDeclared, "manual") {
		t.Fatalf("missing config evidence: %v", got.Evidence)
	}
	risk, ok := hasRisk(got, KindManualRenewalAfterLimit)
	if !ok || risk.Effective != "2027-03-15T00:00:00Z" {
		t.Fatalf("manual renewal risk = %+v ok=%v", risk, ok)
	}
}

// TestClassifyConfigRisks covers the ADR 0006 decision 6 findings.
func TestClassifyConfigRisks(t *testing.T) {
	cases := []struct {
		name          string
		notBefore     string
		notAfter      string
		now           string
		manager       *Manager
		wantKind      string
		wantEffective string
		wantAbsent    bool
	}{
		{
			// Source: https://cert-manager.io/docs/usage/certificate/ (spec.duration must be greater than spec.renewBefore)
			name:      "renewBefore at the lifetime renews in a loop now",
			notBefore: "2026-01-01T00:00:00Z", notAfter: "2026-04-01T00:00:00Z", now: "2026-02-01T00:00:00Z",
			manager:  &Manager{IssuerType: "acme", RenewBefore: "2400h0m0s"},
			wantKind: KindRenewBeforeExceedsLifetime,
		},
		{
			name:      "renewBefore reaches the next CA/B limit",
			notBefore: "2026-01-01T00:00:00Z", notAfter: "2026-09-08T00:00:00Z", now: "2026-02-01T00:00:00Z",
			manager:  &Manager{IssuerType: "acme", RenewBefore: "4800h0m0s"},
			wantKind: KindRenewBeforeLoopAtNextLimit, wantEffective: "2026-03-15T00:00:00Z",
		},
		{
			// Source: https://letsencrypt.org/2025/12/02/from-90-to-45 (VERIFY the 64-day step date)
			name:      "renewBefore reaches the next Let's Encrypt lifetime",
			notBefore: "2026-06-01T00:00:00Z", notAfter: "2026-08-30T00:00:00Z", now: "2026-06-02T00:00:00Z",
			manager:  &Manager{IssuerType: "acme", ACMEServer: "https://acme-v02.api.letsencrypt.org/directory", RenewBefore: "1680h0m0s"},
			wantKind: KindRenewBeforeLoopAtNextLimit, wantEffective: "2027-02-10T00:00:00Z",
		},
		{
			name:      "duration over the next limit for a public ACME CA",
			notBefore: "2026-06-01T00:00:00Z", notAfter: "2026-08-30T00:00:00Z", now: "2026-06-02T00:00:00Z",
			manager:  &Manager{IssuerType: "acme", ACMEServer: "https://acme-v02.api.letsencrypt.org/directory", Duration: "3000h0m0s"},
			wantKind: KindDurationExceedsNextLimit, wantEffective: "2027-03-15T00:00:00Z",
		},
		{
			name:      "unknown ACME server produces no duration finding",
			notBefore: "2026-06-01T00:00:00Z", notAfter: "2026-08-30T00:00:00Z", now: "2026-06-02T00:00:00Z",
			manager:    &Manager{IssuerType: "acme", ACMEServer: "https://acme.internal.example/directory", Duration: "3000h0m0s"},
			wantKind:   KindDurationExceedsNextLimit,
			wantAbsent: true,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			in := inputAt(test.notBefore, test.notAfter, test.now)
			in.Manager = test.manager
			got := Classify(in)
			risk, ok := hasRisk(got, test.wantKind)
			if test.wantAbsent {
				if ok {
					t.Fatalf("unexpected risk %+v", risk)
				}
				return
			}
			if !ok {
				t.Fatalf("missing risk %s in %v", test.wantKind, got.Risks)
			}
			if test.wantEffective != "" && risk.Effective != test.wantEffective {
				t.Fatalf("effective = %q, want %q", risk.Effective, test.wantEffective)
			}
		})
	}
}

// TestClassifyCadenceEvidence pins ADR 0006 decision 5: the CT cadence is
// evidence, never the classification.
func TestClassifyCadenceEvidence(t *testing.T) {
	in := inputAt("2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "2026-02-01T00:00:00Z")
	in.HasCT = true
	in.Names = []string{"example.com", "www.example.com"}
	in.CT = []Issuance{
		{Names: []string{"example.com"}, NotBefore: at("2026-01-01T00:00:00Z")},
		{Names: []string{"www.example.com"}, NotBefore: at("2025-11-02T00:00:00Z")},
		{Names: []string{"example.com"}, NotBefore: at("2025-09-23T00:00:00Z")},
		{Names: []string{"unrelated.example.net"}, NotBefore: at("2025-09-01T00:00:00Z")},
	}
	got := Classify(in)
	if got.Mode != ModeUnknown {
		t.Fatalf("mode = %s, want unknown; cadence is never a classification", got.Mode)
	}
	if !hasEvidence(got, SourceCT, FactCTIssuances365d, "3") {
		t.Fatalf("missing ct-issuances-365d=3: %v", got.Evidence)
	}
	if !hasEvidence(got, SourceCT, FactCTMedianIntervalDays, "50") {
		t.Fatalf("missing ct-median-interval-days=50: %v", got.Evidence)
	}
}

// TestClassifyIsDeterministic checks the evidence and risks are sorted, so the
// same input gives byte-identical output.
func TestClassifyIsDeterministic(t *testing.T) {
	in := inputAt("2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "2026-02-01T00:00:00Z")
	in.Manager = &Manager{IssuerType: "acme", Ready: "False", RenewBefore: "2400h0m0s", Duration: "3000h0m0s", ACMEServer: "https://acme-v02.api.letsencrypt.org/directory"}
	in.DeclaredMode = ModeManual
	first, second := Classify(in), Classify(in)
	if len(first.Evidence) != len(second.Evidence) || len(first.Risks) != len(second.Risks) {
		t.Fatalf("unstable lengths: %+v vs %+v", first, second)
	}
	for index := range first.Evidence {
		if first.Evidence[index] != second.Evidence[index] {
			t.Fatalf("evidence not deterministic at %d", index)
		}
	}
	for index := range first.Risks {
		if first.Risks[index] != second.Risks[index] {
			t.Fatalf("risks not deterministic at %d", index)
		}
	}
	// An automatic mechanism wins over the config declaration.
	if first.Mode != ModeAutomatic {
		t.Fatalf("mode = %s, want automatic (Certificate owns the renewal loop)", first.Mode)
	}
}

func TestSummarizeOwners(t *testing.T) {
	certificates := []OwnerCertificate{
		{Owners: []Owner{{Value: "team-web", Source: "label"}}, Mode: ModeAutomatic, Health: HealthHealthy},
		{Owners: []Owner{{Value: "team-web", Source: "label"}}, Mode: ModeAutomatic, Health: HealthDegraded},
		{Owners: []Owner{{Value: "team-db", Source: "mapping-file"}}, Mode: ModeManual, Health: HealthUnknown},
		{Owners: nil, Mode: ModeUnknown, Health: HealthUnknown},
	}
	got := SummarizeOwners(certificates)
	if len(got) != 3 {
		t.Fatalf("owners = %d, want 3: %+v", len(got), got)
	}
	if got[0].Owner != unownedOwner || got[0].Certificates != 1 || got[0].Unknown != 1 {
		t.Fatalf("unowned bucket = %+v", got[0])
	}
	web := got[1]
	if web.Owner != "team-db" || web.Manual != 1 || web.ManualRenewalsPerYear.Days100 != 4 || web.ManualRenewalsPerYear.Days47 != 8 {
		t.Fatalf("manual bucket = %+v", web)
	}
	team := got[2]
	if team.Owner != "team-web" || team.Certificates != 2 || team.Automatic != 2 || team.Degraded != 1 || team.OwnerSource != "label" {
		t.Fatalf("web bucket = %+v", team)
	}
}

func TestRenewalsPerYear(t *testing.T) {
	cases := map[int]int{200: 2, 100: 4, 47: 8, 90: 5, 0: 0}
	for days, want := range cases {
		if got := renewalsPerYear(days); got != want {
			t.Errorf("renewalsPerYear(%d) = %d, want %d", days, got, want)
		}
	}
}

func TestDirectoryHost(t *testing.T) {
	cases := map[string]string{
		"https://acme-v02.api.letsencrypt.org/directory": "acme-v02.api.letsencrypt.org",
		"acme-v02.api.letsencrypt.org":                   "acme-v02.api.letsencrypt.org",
		"":                                               "",
	}
	for server, want := range cases {
		if got := directoryHost(server); got != want {
			t.Errorf("directoryHost(%q) = %q, want %q", server, got, want)
		}
	}
	if Classify(Input{Now: at("2026-02-01T00:00:00Z")}).Mode != ModeUnknown {
		t.Fatal("expected unknown mode for empty input")
	}
}
