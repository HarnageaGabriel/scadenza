package renewal

import (
	"fmt"
	"testing"
)

// hasFact reports whether the classification carries the evidence fact, with
// any value.
func hasFact(classification Classification, source, fact string) bool {
	for _, item := range classification.Evidence {
		if item.Source == source && item.Fact == fact {
			return true
		}
	}
	return false
}

// TestCadenceCountsPrecertificateAndFinalOnce pins the cadence identity for a
// source that carries no serial: the precertificate and the final certificate
// of one issuance are two log entries with different fingerprints but the same
// names, notBefore, and issuer, so they are one issuance. Counting them twice
// reported two issuances where there was one, and a median interval of zero
// days, which reads as "renew every zero days".
func TestCadenceCountsPrecertificateAndFinalOnce(t *testing.T) {
	in := inputAt("2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "2026-02-01T00:00:00Z")
	in.Names = []string{"example.com"}
	in.CT = []Issuance{
		{Names: []string{"example.com"}, NotBefore: at("2026-01-15T00:00:00Z"), Issuer: "CN=Example CA", Fingerprint: "fp1"},
		{Names: []string{"example.com"}, NotBefore: at("2026-01-15T00:00:00Z"), Issuer: "CN=Example CA", Fingerprint: "fp2"},
	}
	got := Classify(in)
	if !hasEvidence(got, SourceCT, FactCTIssuances365d, "1") {
		t.Fatalf("ct-issuances-365d = %v, want 1", got.Evidence)
	}
	if hasFact(got, SourceCT, FactCTMedianIntervalDays) {
		t.Fatalf("ct-median-interval-days = %v, want none for a single issuance", got.Evidence)
	}
}

// TestCadenceCountsSerialRecordsOnce pins that the serial identity is
// unchanged: the precertificate and the final certificate of one issuance
// share the issuer and serial, so they count once.
func TestCadenceCountsSerialRecordsOnce(t *testing.T) {
	in := inputAt("2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "2026-02-01T00:00:00Z")
	in.Names = []string{"example.com"}
	in.CT = []Issuance{
		{Names: []string{"example.com"}, NotBefore: at("2026-01-15T00:00:00Z"), Issuer: "CN=Example CA", Serial: "0a", Fingerprint: "fp1"},
		{Names: []string{"example.com"}, NotBefore: at("2026-01-15T00:00:00Z"), Issuer: "CN=Example CA", Serial: "0a", Fingerprint: "fp2"},
	}
	got := Classify(in)
	if !hasEvidence(got, SourceCT, FactCTIssuances365d, "1") {
		t.Fatalf("ct-issuances-365d = %v, want 1", got.Evidence)
	}
	if hasFact(got, SourceCT, FactCTMedianIntervalDays) {
		t.Fatalf("ct-median-interval-days = %v, want none for a single issuance", got.Evidence)
	}
}

// TestCadenceCountsRealRenewals pins that two renewals that really happened
// are two issuances with a median interval of the days between them, whether
// or not the records carry a serial.
func TestCadenceCountsRealRenewals(t *testing.T) {
	in := inputAt("2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "2026-02-01T00:00:00Z")
	in.Names = []string{"example.com"}
	in.CT = []Issuance{
		{Names: []string{"example.com"}, NotBefore: at("2025-11-02T00:00:00Z"), Issuer: "CN=Example CA", Fingerprint: "fp1"},
		{Names: []string{"example.com"}, NotBefore: at("2026-01-01T00:00:00Z"), Issuer: "CN=Example CA", Fingerprint: "fp2"},
	}
	got := Classify(in)
	if !hasEvidence(got, SourceCT, FactCTIssuances365d, "2") {
		t.Fatalf("ct-issuances-365d = %v, want 2", got.Evidence)
	}
	if !hasEvidence(got, SourceCT, FactCTMedianIntervalDays, "60") {
		t.Fatalf("ct-median-interval-days = %v, want 60", got.Evidence)
	}
}

// TestCadenceMedianOfThreeIssuances pins the median over the intervals
// between distinct issuances: three renewals 30 and 60 days apart have a
// median interval of 45 days.
func TestCadenceMedianOfThreeIssuances(t *testing.T) {
	in := inputAt("2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "2026-02-01T00:00:00Z")
	in.Names = []string{"example.com"}
	in.CT = []Issuance{
		{Names: []string{"example.com"}, NotBefore: at("2025-11-01T00:00:00Z"), Issuer: "CN=Example CA", Fingerprint: "fp1"},
		{Names: []string{"example.com"}, NotBefore: at("2025-12-01T00:00:00Z"), Issuer: "CN=Example CA", Fingerprint: "fp2"},
		{Names: []string{"example.com"}, NotBefore: at("2026-01-30T00:00:00Z"), Issuer: "CN=Example CA", Fingerprint: "fp3"},
	}
	got := Classify(in)
	if !hasEvidence(got, SourceCT, FactCTIssuances365d, "3") {
		t.Fatalf("ct-issuances-365d = %v, want 3", got.Evidence)
	}
	if !hasEvidence(got, SourceCT, FactCTMedianIntervalDays, "45") {
		t.Fatalf("ct-median-interval-days = %v, want 45", got.Evidence)
	}
}

// TestCadenceCollapsesIssuancesWithinAnHour pins the defensive collapse: a
// certificate is not renewed twice within an hour, so two records that close
// are one issuance, and a median interval of zero days is never reported.
func TestCadenceCollapsesIssuancesWithinAnHour(t *testing.T) {
	cases := []struct {
		name         string
		second       string
		wantIssuance string
	}{
		{"thirty minutes apart collapse into the earlier issuance", "2026-01-15T00:30:00Z", "1"},
		{"exactly one hour apart are two issuances", "2026-01-15T01:00:00Z", "2"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			in := inputAt("2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "2026-02-01T00:00:00Z")
			in.Names = []string{"example.com"}
			in.CT = []Issuance{
				{Names: []string{"example.com"}, NotBefore: at("2026-01-15T00:00:00Z"), Issuer: "CN=Example CA", Fingerprint: "fp1"},
				{Names: []string{"example.com"}, NotBefore: at(test.second), Issuer: "CN=Example CA", Fingerprint: "fp2"},
			}
			got := Classify(in)
			if !hasEvidence(got, SourceCT, FactCTIssuances365d, test.wantIssuance) {
				t.Fatalf("ct-issuances-365d = %v, want %s", got.Evidence, test.wantIssuance)
			}
			if hasFact(got, SourceCT, FactCTMedianIntervalDays) {
				t.Fatalf("ct-median-interval-days = %v, want none for issuances an hour apart", got.Evidence)
			}
		})
	}
}

// TestCadenceWindowAndNowAreRespected pins the fixed 365-day window and the
// evaluation instant for records that carry no serial: a record outside the
// window is not counted, and a record issued after the evaluation instant is
// ignored.
func TestCadenceWindowAndNowAreRespected(t *testing.T) {
	in := inputAt("2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "2026-02-01T00:00:00Z")
	in.Names = []string{"example.com"}
	inside := Issuance{Names: []string{"example.com"}, NotBefore: at("2026-01-15T00:00:00Z"), Issuer: "CN=Example CA", Fingerprint: "fp1"}
	outside := Issuance{Names: []string{"example.com"}, NotBefore: at("2024-12-31T00:00:00Z"), Issuer: "CN=Example CA", Fingerprint: "fp2"}
	future := Issuance{Names: []string{"example.com"}, NotBefore: at("2026-03-01T00:00:00Z"), Issuer: "CN=Example CA", Fingerprint: "fp3"}
	in.CT = []Issuance{inside, outside}
	got := Classify(in)
	if !hasEvidence(got, SourceCT, FactCTIssuances365d, "1") {
		t.Fatalf("ct-issuances-365d = %v, want 1", got.Evidence)
	}
	in.CT = []Issuance{inside, outside, future}
	ignored := Classify(in)
	if fmt.Sprint(ignored.Evidence) != fmt.Sprint(got.Evidence) {
		t.Fatalf("a record after the evaluation instant changed the evidence: %v vs %v", ignored.Evidence, got.Evidence)
	}
}
