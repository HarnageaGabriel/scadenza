package inventory

import (
	"strings"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/kube"
	"github.com/HarnageaGabriel/scadenza/internal/tlsprobe"
	"github.com/google/go-cmp/cmp"
)

// TestNormalizeFingerprint pins the canonical fingerprint form: lowercase
// hexadecimal with the colons, the spaces and the 0x prefix removed, so the
// same certificate written in two ways is one certificate.
func TestNormalizeFingerprint(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"AA:BB:CC:DD", "aabbccdd"},
		{"aa:bb:cc:dd", "aabbccdd"},
		{"0xAABB", "aabb"},
		{"0XAABB", "aabb"},
		{"aa bb", "aabb"},
		{" aabb ", "aabb"},
		{"", ""},
	}
	for _, test := range tests {
		if got := normalizeFingerprint(test.input); got != test.want {
			t.Errorf("normalizeFingerprint(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}

// TestNormalizeNameFoldsUnicode pins the canonical name form: lowercase, and
// with every Unicode label folded to its ASCII punycode form, so a name
// written in Unicode in one source and in punycode in another is one name.
func TestNormalizeNameFoldsUnicode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Example.COM", "example.com"},
		{" example.com. ", "example.com"},
		{"*.example.com", "*.example.com"},
		{"münchen.de", "xn--mnchen-3ya.de"},
		{"MÜNCHEN.DE", "xn--mnchen-3ya.de"},
		{"xn--mnchen-3ya.de", "xn--mnchen-3ya.de"},
		{"*.münchen.de", "*.xn--mnchen-3ya.de"},
	}
	for _, test := range tests {
		if got := normalizeName(test.input); got != test.want {
			t.Errorf("normalizeName(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}

// TestFingerprintNormalizationKeepsOneCertificate pins the correlation across
// the sources: a live certificate and a Certificate Transparency record that
// write the same fingerprint differently are one certificate, and so is the
// same certificate read from Kubernetes.
func TestFingerprintNormalizationKeepsOneCertificate(t *testing.T) {
	notBefore := date(1, time.January)
	notAfter := date(2, time.April)
	live := tlsprobe.Result{
		Host: "www.example.com", Port: 443, Fingerprint: "AA:BB:CC:DD", Names: []string{"www.example.com"},
		Issuer: "CN=CA", NotBefore: notBefore, NotAfter: notAfter, Trusted: true,
	}
	record := ct.Certificate{
		Fingerprint: "aabbccdd", SubjectNames: []string{"www.example.com"}, Issuer: "CN=CA",
		NotBefore: notBefore, NotAfter: notAfter, Source: "certspotter", DedupKey: "1",
	}

	t.Run("live and CT are one certificate", func(t *testing.T) {
		certificates, findings := Correlate(Input{
			Domains: []string{"example.com"},
			Live:    []tlsprobe.Result{live},
			CT:      []ct.Certificate{record},
			Now:     date(1, time.February),
		})
		if len(certificates) != 1 {
			t.Fatalf("certificates = %+v, want one certificate", certificates)
		}
		certificate := certificates[0]
		if certificate.Fingerprint != "aabbccdd" {
			t.Errorf("fingerprint = %q, want the normalized aabbccdd", certificate.Fingerprint)
		}
		if certificate.CorrelationMethod != CorrelationSHA256 {
			t.Errorf("correlation_method = %q, want %q", certificate.CorrelationMethod, CorrelationSHA256)
		}
		if len(findings) != 1 || findings[0].Kind != KindMatched {
			t.Fatalf("findings = %+v, want one matched finding", findings)
		}
	})

	t.Run("live and Kubernetes are one certificate", func(t *testing.T) {
		// The Kubernetes record carries the same fingerprint as the live
		// certificate in another notation, so all three sources describe one
		// certificate and it is neither live only nor Kubernetes only.
		certificates, findings := Correlate(Input{
			Domains: []string{"example.com"},
			Live:    []tlsprobe.Result{live},
			CT:      []ct.Certificate{record},
			Kube: []kube.Certificate{{
				Fingerprint: "AA:BB:CC:DD",
				DedupKey:    "secret/web/tls",
				Names:       []string{"www.example.com"},
				NotBefore:   notBefore,
				NotAfter:    notAfter,
			}},
			Now: date(1, time.February),
		})
		if len(certificates) != 1 {
			t.Fatalf("certificates = %+v, want one certificate", certificates)
		}
		if certificates[0].Fingerprint != "aabbccdd" {
			t.Errorf("fingerprint = %q, want the normalized aabbccdd", certificates[0].Fingerprint)
		}
		for _, finding := range findings {
			if finding.Kind == KindLiveOnly || finding.Kind == KindKubeOnly {
				t.Fatalf("finding %q accuses a certificate that was seen in more than one place: %+v", finding.Kind, findings)
			}
		}
	})
}

// TestNameNormalizationKeepsOneCertificate pins the name correlation: a
// Certificate Transparency record in punycode and a Kubernetes record in
// Unicode are one certificate, and a name that differs only in case is listed
// once.
func TestNameNormalizationKeepsOneCertificate(t *testing.T) {
	notBefore := date(1, time.January)
	notAfter := date(2, time.April)

	t.Run("punycode and unicode are one certificate", func(t *testing.T) {
		certificates, _ := Correlate(Input{
			CT: []ct.Certificate{{
				Fingerprint: "aabbccdd", SubjectNames: []string{"xn--mnchen-3ya.de"}, Issuer: "CN=CA",
				NotBefore: notBefore, NotAfter: notAfter, Source: "certspotter", DedupKey: "1",
			}},
			Kube: []kube.Certificate{{
				DedupKey:  "secret/web/tls",
				Names:     []string{"münchen.de"},
				NotBefore: notBefore,
				NotAfter:  notAfter,
			}},
			Now: date(1, time.February),
		})
		if len(certificates) != 1 {
			t.Fatalf("certificates = %+v, want one certificate", certificates)
		}
		certificate := certificates[0]
		if certificate.CorrelationMethod != CorrelationNamesExpiry {
			t.Errorf("correlation_method = %q, want %q", certificate.CorrelationMethod, CorrelationNamesExpiry)
		}
		if diff := cmp.Diff([]string{"xn--mnchen-3ya.de"}, certificate.Names); diff != "" {
			t.Errorf("names (-want +got):\n%s", diff)
		}
	})

	t.Run("a name that differs in case is listed once", func(t *testing.T) {
		certificates, _ := Correlate(Input{
			Domains: []string{"example.com"},
			Live: []tlsprobe.Result{{
				Host: "example.com", Port: 443, Fingerprint: "aa", Names: []string{"Example.COM"},
				Issuer: "CN=CA", NotBefore: notBefore, NotAfter: notAfter, Trusted: true,
			}},
			CT: []ct.Certificate{{
				Fingerprint: "aa", SubjectNames: []string{"example.com"}, Issuer: "CN=CA",
				NotBefore: notBefore, NotAfter: notAfter, Source: "certspotter", DedupKey: "1",
			}},
			Now: date(1, time.February),
		})
		if len(certificates) != 1 {
			t.Fatalf("certificates = %+v, want one certificate", certificates)
		}
		if diff := cmp.Diff([]string{"example.com"}, certificates[0].Names); diff != "" {
			t.Errorf("names (-want +got):\n%s", diff)
		}
	})
}

// TestAmbiguousWeakJoinIsNotAccused pins the ambiguous weak join: when more
// than one Certificate Transparency certificate shares the names and the
// expiry of a Kubernetes record, the record stays unresolved and is never
// accused of being absent from Certificate Transparency.
func TestAmbiguousWeakJoinIsNotAccused(t *testing.T) {
	notBefore := date(1, time.January)
	notAfter := date(2, time.April)
	records := []ct.Certificate{
		{Fingerprint: "aabbccdd", SubjectNames: []string{"example.com"}, Issuer: "CN=CA", NotBefore: notBefore, NotAfter: notAfter, Source: "certspotter", DedupKey: "1"},
		{Fingerprint: "11223344", SubjectNames: []string{"example.com"}, Issuer: "CN=CA", NotBefore: notBefore, NotAfter: notAfter, Source: "crtsh", DedupKey: "2"},
	}
	kubeRecord := kube.Certificate{
		DedupKey:  "secret/web/tls",
		Names:     []string{"example.com"},
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}
	certificates, findings := Correlate(Input{
		Domains: []string{"example.com"},
		CT:      records,
		Kube:    []kube.Certificate{kubeRecord},
		Now:     date(1, time.February),
	})
	if len(certificates) != 3 {
		t.Fatalf("certificates = %+v, want the two CT certificates and one unresolved record", certificates)
	}
	byFingerprint := map[string]Certificate{}
	var unresolved []Certificate
	for _, certificate := range certificates {
		if certificate.Fingerprint == "" {
			unresolved = append(unresolved, certificate)
			continue
		}
		byFingerprint[certificate.Fingerprint] = certificate
	}
	if len(unresolved) != 1 {
		t.Fatalf("unresolved entries = %+v, want exactly one", unresolved)
	}
	if unresolved[0].CorrelationMethod != CorrelationUnresolved {
		t.Errorf("correlation_method = %q, want %q", unresolved[0].CorrelationMethod, CorrelationUnresolved)
	}
	for _, fingerprint := range []string{"aabbccdd", "11223344"} {
		certificate, ok := byFingerprint[fingerprint]
		if !ok {
			t.Fatalf("the CT certificate %q is missing from %+v", fingerprint, certificates)
		}
		if len(certificate.Observations) != 1 {
			t.Errorf("the CT certificate %q changed: observations = %+v", fingerprint, certificate.Observations)
		}
	}
	unknown := []Finding{}
	for _, finding := range findings {
		if finding.Kind == KindKubeOnly {
			t.Fatalf("the ambiguous record was accused of being absent from Certificate Transparency: %+v", findings)
		}
		if finding.Kind == KindUnknown {
			unknown = append(unknown, finding)
		}
	}
	if len(unknown) != 1 {
		t.Fatalf("unknown findings = %+v, want exactly one", unknown)
	}
	want := "the Kubernetes certificate could not be matched to one Certificate Transparency certificate because 2 share its names and expiry"
	if unknown[0].Detail != want {
		t.Errorf("detail = %q, want %q", unknown[0].Detail, want)
	}
}

// TestAmbiguousWeakJoinWithALiveCertificate pins the same rule when the
// candidates are not all Certificate Transparency certificates: the record
// still stays unresolved and is never accused of being absent.
func TestAmbiguousWeakJoinWithALiveCertificate(t *testing.T) {
	notBefore := date(1, time.January)
	notAfter := date(2, time.April)
	certificates, findings := Correlate(Input{
		Domains: []string{"example.com"},
		Live: []tlsprobe.Result{{
			Host: "example.com", Port: 443, Fingerprint: "aabbccdd", Names: []string{"example.com"},
			Issuer: "CN=CA", NotBefore: notBefore, NotAfter: notAfter, Trusted: true,
		}},
		CT: []ct.Certificate{{
			Fingerprint: "11223344", SubjectNames: []string{"example.com"}, Issuer: "CN=CA",
			NotBefore: notBefore, NotAfter: notAfter, Source: "certspotter", DedupKey: "1",
		}},
		Kube: []kube.Certificate{{
			DedupKey:  "secret/web/tls",
			Names:     []string{"example.com"},
			NotBefore: notBefore,
			NotAfter:  notAfter,
		}},
		Now: date(1, time.February),
	})
	if len(certificates) != 3 {
		t.Fatalf("certificates = %+v, want the live certificate, the CT certificate and one unresolved record", certificates)
	}
	unknown := []Finding{}
	for _, finding := range findings {
		if finding.Kind == KindKubeOnly {
			t.Fatalf("the ambiguous record was accused of being absent from Certificate Transparency: %+v", findings)
		}
		if finding.Kind == KindUnknown {
			unknown = append(unknown, finding)
		}
	}
	if len(unknown) != 1 {
		t.Fatalf("unknown findings = %+v, want exactly one", unknown)
	}
	if !strings.Contains(unknown[0].Detail, "2 share its names and expiry") {
		t.Errorf("detail = %q, want the count of the certificates that share the names and the expiry", unknown[0].Detail)
	}
}

// TestIssuerSerialMergeRequiresASharedName pins the issuer and serial merge: a
// Certificate Transparency record without a fingerprint is only merged into a
// live certificate that shares a name with it, because the same issuer can
// issue several certificates with the same serial number.
func TestIssuerSerialMergeRequiresASharedName(t *testing.T) {
	notBefore := date(1, time.January)
	notAfter := date(2, time.April)
	api := tlsprobe.Result{
		Host: "api.example.com", Port: 443, Fingerprint: "aa11", Serial: "01", Issuer: "CN=Dev CA",
		Names: []string{"api.example.com"}, NotBefore: notBefore, NotAfter: notAfter, Trusted: true,
	}
	shop := tlsprobe.Result{
		Host: "shop.example.com", Port: 443, Fingerprint: "bb22", Serial: "01", Issuer: "CN=Dev CA",
		Names: []string{"shop.example.com"}, NotBefore: notBefore, NotAfter: notAfter, Trusted: true,
	}
	record := ct.Certificate{
		Serial: "1", Issuer: "CN=Dev CA", SubjectNames: []string{"shop.example.com"},
		NotBefore: notBefore, NotAfter: notAfter, Source: "crtsh", DedupKey: "1",
	}

	t.Run("the record merges into the entry that shares a name", func(t *testing.T) {
		certificates, _ := Correlate(Input{
			Domains: []string{"example.com"},
			Live:    []tlsprobe.Result{api, shop},
			CT:      []ct.Certificate{record},
			Now:     date(1, time.February),
		})
		if len(certificates) != 2 {
			t.Fatalf("certificates = %+v, want the two live certificates", certificates)
		}
		byFingerprint := map[string]Certificate{}
		for _, certificate := range certificates {
			byFingerprint[certificate.Fingerprint] = certificate
		}
		merged, ok := byFingerprint["bb22"]
		if !ok {
			t.Fatalf("the bb22 entry is missing from %+v", certificates)
		}
		if len(merged.Observations) != 2 {
			t.Fatalf("the CT record did not merge into bb22: observations = %+v", merged.Observations)
		}
		if merged.CorrelationMethod != CorrelationIssuerSerial {
			t.Errorf("correlation_method = %q, want %q", merged.CorrelationMethod, CorrelationIssuerSerial)
		}
		if alone, ok := byFingerprint["aa11"]; !ok {
			t.Fatalf("the aa11 entry is missing from %+v", certificates)
		} else if len(alone.Observations) != 1 {
			t.Errorf("the CT record was merged into aa11: observations = %+v", alone.Observations)
		}
	})

	t.Run("no name in common keeps the record separate", func(t *testing.T) {
		other := record
		other.SubjectNames = []string{"other.example.com"}
		certificates, _ := Correlate(Input{
			Domains: []string{"example.com"},
			Live:    []tlsprobe.Result{api, shop},
			CT:      []ct.Certificate{other},
			Now:     date(1, time.February),
		})
		if len(certificates) != 3 {
			t.Fatalf("certificates = %+v, want the two live certificates and the CT record", certificates)
		}
		for _, certificate := range certificates {
			if certificate.Fingerprint == "" && certificate.CorrelationMethod != CorrelationUnresolved {
				t.Errorf("the CT record was correlated: %+v", certificate)
			}
		}
	})

	t.Run("several names in common keep the record separate", func(t *testing.T) {
		twin := shop
		twin.Fingerprint = "cc33"
		certificates, _ := Correlate(Input{
			Domains: []string{"example.com"},
			Live:    []tlsprobe.Result{api, shop, twin},
			CT:      []ct.Certificate{record},
			Now:     date(1, time.February),
		})
		if len(certificates) != 4 {
			t.Fatalf("certificates = %+v, want the three live certificates and the CT record", certificates)
		}
		for _, certificate := range certificates {
			if certificate.Fingerprint == "" && certificate.CorrelationMethod != CorrelationUnresolved {
				t.Errorf("the CT record was correlated: %+v", certificate)
			}
		}
	})
}

// TestNotCompliantDetailPrintsTheRemainder pins the lifetime in the
// not-compliant detail: a lifetime that is not a whole number of days is
// reported with the remainder, so a lifetime of 100 days and one second never
// reads as exactly 100 days.
func TestNotCompliantDetailPrintsTheRemainder(t *testing.T) {
	notBefore := time.Date(2027, 4, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		notAfter time.Time
		want     string
	}{
		{
			name:     "a whole number of days is unchanged",
			notAfter: notBefore.Add(101 * 24 * time.Hour),
			want:     "lifetime 101 days exceeds the 100-day maximum validity in force at issuance",
		},
		{
			name:     "a remainder is reported",
			notAfter: notBefore.Add(100*24*time.Hour + time.Second),
			want:     "lifetime 100 days and 1 second exceeds the 100-day maximum validity in force at issuance",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, findings := Correlate(Input{
				Domains: []string{"example.com"},
				CT: []ct.Certificate{{
					Fingerprint: "aa", SubjectNames: []string{"example.com"}, Issuer: "CN=CA",
					NotBefore: notBefore, NotAfter: test.notAfter, Source: "certspotter", DedupKey: "1",
				}},
				Now: notBefore,
			})
			for _, finding := range findings {
				if finding.Kind != KindNotCompliantAtIssuance {
					continue
				}
				if finding.Detail != test.want {
					t.Fatalf("detail = %q, want %q", finding.Detail, test.want)
				}
				return
			}
			t.Fatalf("no not-compliant finding in %+v", findings)
		})
	}
}
