package inventory

import (
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/tlsprobe"
)

func TestCorrelationMethodStatesStrength(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.AddDate(0, 0, 90)
	live := []tlsprobe.Result{{
		Fingerprint: fingerprint("a"), Serial: "0a", Issuer: "CN=Example", Host: "api.example.com", Port: 443,
		Names: []string{"api.example.com"}, Trusted: true, NotBefore: notBefore, NotAfter: notAfter,
	}}
	records := []ct.Certificate{
		{DedupKey: "serial-only", Serial: "0a", Issuer: "CN=Example", SubjectNames: []string{"api.example.com"}, NotBefore: notBefore, NotAfter: notAfter, Source: "crtsh"},
		{DedupKey: "fp", Fingerprint: fingerprint("b"), SubjectNames: []string{"www.example.com"}, NotBefore: notBefore, NotAfter: notAfter, Source: "certspotter"},
		{DedupKey: "opaque", SubjectNames: []string{"opaque.example.com"}, NotBefore: notBefore, NotAfter: notAfter, Source: "crtsh"},
	}
	certificates, _ := Correlate(Input{Domains: []string{"example.com"}, Live: live, CT: records, Now: notBefore})

	methods := map[string]string{}
	for _, certificate := range certificates {
		key := certificate.Fingerprint
		if key == "" {
			key = certificate.Serial + "|" + join(certificate.Names)
		}
		methods[key] = certificate.CorrelationMethod
		if certificate.Policy.MaxValidityAtIssuanceDays == 0 {
			t.Errorf("certificate %v has no policy assessment", certificate.Names)
		}
	}
	if methods[fingerprint("a")] != CorrelationIssuerSerial {
		t.Errorf("live+crtsh fingerprint entry = %q, want issuer_serial", methods[fingerprint("a")])
	}
	if methods[fingerprint("b")] != CorrelationSHA256 {
		t.Errorf("fingerprint entry = %q, want sha256", methods[fingerprint("b")])
	}
	unresolved := false
	for _, method := range methods {
		if method == CorrelationUnresolved {
			unresolved = true
		}
	}
	if !unresolved {
		t.Errorf("expected an unresolved entry, got %v", methods)
	}
}

func TestNewCoverage(t *testing.T) {
	coverage := NewCoverage(3, 2, 1, 2, []SourceCoverage{{Name: "tls", Status: SourceStatusPartial}})
	if coverage.Ratio != 0.6667 {
		t.Errorf("ratio = %v, want 0.6667", coverage.Ratio)
	}
	if empty := NewCoverage(0, 0, 0, 0, nil); empty.Ratio != 1 {
		t.Errorf("empty ratio = %v, want 1", empty.Ratio)
	}
	capped := NewCoverage(1, 2, 0, 0, nil)
	if capped.Ratio != 1 {
		t.Errorf("ratio = %v, want capped at 1", capped.Ratio)
	}
}

func fingerprint(letter string) string {
	result := ""
	for range 64 {
		result += letter
	}
	return result
}

func join(values []string) string {
	out := ""
	for _, value := range values {
		out += value
	}
	return out
}
