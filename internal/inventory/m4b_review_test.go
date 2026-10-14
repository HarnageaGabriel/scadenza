package inventory

import (
	"strings"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/renewal"
)

// TestRenewalCadenceCollapsesOneIssuance is the inventory half of M4b review
// finding 6: the fingerprint and serial of every CT record reach the renewal
// package, so a precertificate and the final certificate of one issuance, which
// the inventory holds as two entries, count once in the cadence evidence.
func TestRenewalCadenceCollapsesOneIssuance(t *testing.T) {
	notBefore := time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.AddDate(0, 0, 90)
	records := []ct.Certificate{
		{DedupKey: "precert", Fingerprint: fingerprint("a"), Serial: "1a", Issuer: "CN=Example", SubjectNames: []string{"example.com"}, NotBefore: notBefore, NotAfter: notAfter, Source: "certspotter"},
		{DedupKey: "final", Fingerprint: fingerprint("b"), Serial: "1a", Issuer: "CN=Example", SubjectNames: []string{"example.com"}, NotBefore: notBefore, NotAfter: notAfter, Source: "crtsh"},
	}
	certificates, _ := Correlate(Input{Domains: []string{"example.com"}, CT: records, Now: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)})
	if len(certificates) != 2 {
		t.Fatalf("certificates = %d, want 2 (one per fingerprint)", len(certificates))
	}
	for _, certificate := range certificates {
		found := false
		for _, evidence := range certificate.Renewal.Evidence {
			if evidence.Source == renewal.SourceCT && evidence.Fact == renewal.FactCTIssuances365d {
				found = true
				if evidence.Value != "1" {
					t.Fatalf("ct-issuances-365d = %q, want 1 for %s", evidence.Value, certificate.Fingerprint)
				}
			}
		}
		if !found {
			t.Fatalf("no cadence evidence for %s: %v", certificate.Fingerprint, certificate.Renewal.Evidence)
		}
	}
}

// TestRenewalCadenceDeduplicatesOverlappingQueries is the other half: the same
// record returned by two overlapping domain queries counts once as well.
func TestRenewalCadenceDeduplicatesOverlappingQueries(t *testing.T) {
	notBefore := time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.AddDate(0, 0, 90)
	record := ct.Certificate{DedupKey: "one", Fingerprint: fingerprint("c"), Serial: "2b", Issuer: "CN=Example", SubjectNames: []string{"example.com", "www.example.com"}, NotBefore: notBefore, NotAfter: notAfter, Source: "certspotter"}
	records := []ct.Certificate{record, record}
	certificates, _ := Correlate(Input{Domains: []string{"example.com"}, CT: records, Now: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)})
	if len(certificates) != 1 {
		t.Fatalf("certificates = %d, want 1", len(certificates))
	}
	if !strings.Contains(evidenceValue(certificates[0].Renewal.Evidence), "ct-issuances-365d=1") {
		t.Fatalf("evidence = %v", certificates[0].Renewal.Evidence)
	}
}

func evidenceValue(evidence []renewal.Evidence) string {
	parts := make([]string, 0, len(evidence))
	for _, item := range evidence {
		parts = append(parts, item.Fact+"="+item.Value)
	}
	return strings.Join(parts, ",")
}
