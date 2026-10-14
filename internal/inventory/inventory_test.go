package inventory

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/tlsprobe"
	"github.com/google/go-cmp/cmp"
)

func date(day int, month time.Month) time.Time {
	return time.Date(2026, month, day, 0, 0, 0, 0, time.UTC)
}

func TestCorrelateDiffCategories(t *testing.T) {
	now := date(1, time.February)
	tests := []struct {
		name        string
		ct          []ct.Certificate
		live        []tlsprobe.Result
		errs        []ProbeError
		unprobed    map[string]string
		domains     []string
		wantKinds   []string
		wantDetail  map[string]string
		wantFP      string
		wantPublic  *bool
		wantVerdict string
	}{
		{
			name:      "matched by fingerprint",
			domains:   []string{"example.com"},
			ct:        []ct.Certificate{{Fingerprint: "aa", SubjectNames: []string{"example.com", "www.example.com"}, Issuer: "CN=CA", NotBefore: date(1, time.January), NotAfter: date(2, time.April), Source: "certspotter", DedupKey: "1"}},
			live:      []tlsprobe.Result{{Host: "www.example.com", Port: 443, Fingerprint: "aa", Names: []string{"www.example.com"}, Issuer: "CN=CA", NotBefore: date(1, time.January), NotAfter: date(2, time.April), Trusted: true}},
			wantKinds: []string{KindMatched},
			wantFP:    "aa",
		},
		{
			name:      "ct only and live only",
			domains:   []string{"example.com"},
			ct:        []ct.Certificate{{Fingerprint: "bb", SubjectNames: []string{"shop.example.com"}, Issuer: "CN=CA", NotBefore: date(1, time.January), NotAfter: date(2, time.April), Source: "certspotter", DedupKey: "2"}},
			live:      []tlsprobe.Result{{Host: "shop.example.com", Port: 443, Fingerprint: "cc", Names: []string{"shop.example.com"}, Issuer: "CN=Other", NotBefore: date(1, time.January), NotAfter: date(2, time.April), Trusted: false}},
			wantKinds: []string{KindCTOnly, KindLiveOnly},
			wantDetail: map[string]string{
				KindLiveOnly: "private_or_untrusted",
				KindCTOnly:   "not presented",
			},
		},
		{
			name:      "not checked wildcard",
			domains:   []string{"example.com"},
			ct:        []ct.Certificate{{Fingerprint: "ww", SubjectNames: []string{"*.example.com"}, Issuer: "CN=CA", NotBefore: date(1, time.January), NotAfter: date(2, time.April), Source: "certspotter", DedupKey: "3"}},
			unprobed:  map[string]string{"*.example.com": "wildcard"},
			wantKinds: []string{KindNotChecked},
		},
		{
			name:      "not checked probe error",
			domains:   []string{"example.com"},
			ct:        []ct.Certificate{{Fingerprint: "ee", SubjectNames: []string{"api.example.com"}, Issuer: "CN=CA", NotBefore: date(1, time.January), NotAfter: date(2, time.April), Source: "certspotter", DedupKey: "4"}},
			errs:      []ProbeError{{Host: "api.example.com", Port: 443, Class: "refused"}},
			wantKinds: []string{KindNotChecked},
		},
		{
			name:      "not checked expired",
			domains:   []string{"example.com"},
			ct:        []ct.Certificate{{Fingerprint: "ex", SubjectNames: []string{"old.example.com"}, Issuer: "CN=CA", NotBefore: date(1, time.May), NotAfter: date(1, time.June), Source: "certspotter", DedupKey: "5"}},
			wantKinds: []string{KindNotChecked},
		},
		{
			name:      "unknown without fingerprint or serial",
			domains:   []string{"example.com"},
			ct:        []ct.Certificate{{SubjectNames: []string{"x.example.com"}, Issuer: "CN=CA", NotBefore: date(1, time.January), NotAfter: date(2, time.April), Source: "crtsh", DedupKey: "6"}},
			wantKinds: []string{KindUnknown},
		},
		{
			name:    "crtsh correlates by issuer and serial",
			domains: []string{"example.com"},
			ct: []ct.Certificate{{
				SubjectNames: []string{"x.example.com"}, Issuer: "CN=Example CA, O=Org", Serial: "ABC",
				NotBefore: date(1, time.January), NotAfter: date(2, time.April), Source: "crtsh", DedupKey: "10:ABC",
			}},
			live: []tlsprobe.Result{{
				Host: "x.example.com", Port: 443, Fingerprint: "ff", Serial: "0abc", Names: []string{"x.example.com"},
				Issuer: "O=Org, CN=Example CA", NotBefore: date(1, time.January), NotAfter: date(2, time.April), Trusted: true,
			}},
			wantKinds: []string{KindMatched},
			wantFP:    "ff",
		},
		{
			name:        "exceeds 100 days",
			domains:     []string{"example.com"},
			ct:          []ct.Certificate{{Fingerprint: "gg", SubjectNames: []string{"long.example.com"}, Issuer: "CN=CA", NotBefore: date(1, time.January), NotAfter: date(20, time.July), Source: "certspotter", DedupKey: "7"}},
			live:        []tlsprobe.Result{{Host: "long.example.com", Port: 443, Fingerprint: "gg", Names: []string{"long.example.com"}, Issuer: "CN=CA", NotBefore: date(1, time.January), NotAfter: date(20, time.July), Trusted: true}},
			wantKinds:   []string{KindExceeds100D, KindMatched},
			wantVerdict: "exceeds",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := Input{Domains: test.domains, CT: test.ct, Live: test.live, Errors: test.errs, Unprobed: test.unprobed, Now: now}
			certificates, findings := Correlate(input)
			again, againFindings := Correlate(input)
			if diff := cmp.Diff(certificates, again); diff != "" {
				t.Fatalf("non-deterministic certificates (-first +second):\n%s", diff)
			}
			if diff := cmp.Diff(findings, againFindings); diff != "" {
				t.Fatalf("non-deterministic findings (-first +second):\n%s", diff)
			}
			kinds := make([]string, 0, len(findings))
			for _, finding := range findings {
				kinds = append(kinds, finding.Kind)
			}
			slices.Sort(kinds)
			want := slices.Clone(test.wantKinds)
			slices.Sort(want)
			if diff := cmp.Diff(want, kinds); diff != "" {
				t.Fatalf("finding kinds mismatch (-want +got):\n%s", diff)
			}
			for _, finding := range findings {
				if substring, ok := test.wantDetail[finding.Kind]; ok && !strings.Contains(finding.Detail, substring) {
					t.Errorf("%s detail %q missing %q", finding.Kind, finding.Detail, substring)
				}
			}
			if test.wantFP != "" {
				found := false
				for _, certificate := range certificates {
					if certificate.Fingerprint == test.wantFP {
						found = true
					}
				}
				if !found {
					t.Fatalf("fingerprint %q absent from %v", test.wantFP, certificates)
				}
			}
			if test.wantVerdict != "" {
				matched := false
				for _, certificate := range certificates {
					if certificate.Verdict100D == test.wantVerdict {
						matched = true
					}
				}
				if !matched {
					t.Fatalf("verdict %q absent from %v", test.wantVerdict, certificates)
				}
			}
		})
	}
}

func TestCorrelatePublicAndLifetime(t *testing.T) {
	now := date(1, time.February)
	certificates, _ := Correlate(Input{
		Domains: []string{"example.com"},
		CT:      []ct.Certificate{{Fingerprint: "aa", SubjectNames: []string{"example.com"}, Issuer: "CN=CA", NotBefore: date(1, time.January), NotAfter: date(1, time.April), Source: "certspotter", DedupKey: "1"}},
		Live:    []tlsprobe.Result{{Host: "example.com", Port: 443, Fingerprint: "aa", Names: []string{"example.com"}, Issuer: "CN=CA", NotBefore: date(1, time.January), NotAfter: date(1, time.April), Trusted: true}},
		Now:     now,
	})
	if len(certificates) != 1 {
		t.Fatalf("certificates = %v", certificates)
	}
	certificate := certificates[0]
	if certificate.Public == nil || !*certificate.Public {
		t.Fatalf("public = %v", certificate.Public)
	}
	if certificate.LifetimeDays != 90 || certificate.Verdict100D != "ok" {
		t.Fatalf("lifetime = %d/%s", certificate.LifetimeDays, certificate.Verdict100D)
	}
	if len(certificate.Observations) != 2 {
		t.Fatalf("observations = %v", certificate.Observations)
	}

	ctOnly, _ := Correlate(Input{
		Domains: []string{"example.com"},
		CT:      []ct.Certificate{{Fingerprint: "zz", SubjectNames: []string{"other.example.com"}, Issuer: "CN=CA", NotBefore: date(1, time.January), NotAfter: date(1, time.April), Source: "crtsh", DedupKey: "9"}},
		Now:     now,
	})
	if len(ctOnly) != 1 || ctOnly[0].Public != nil {
		t.Fatalf("CT-only public = %v", ctOnly)
	}
}

func TestNormalization(t *testing.T) {
	issuerPairs := [][2]string{
		{"CN=Example CA, O=Org", "O=Org,CN=Example CA"},
		{"/C=US/O=Org/CN=Example", "CN=Example, O=Org, C=US"},
	}
	for _, pair := range issuerPairs {
		if normalizeIssuer(pair[0]) != normalizeIssuer(pair[1]) {
			t.Errorf("normalizeIssuer(%q) = %q, normalizeIssuer(%q) = %q", pair[0], normalizeIssuer(pair[0]), pair[1], normalizeIssuer(pair[1]))
		}
	}
	for _, serial := range []string{"00AB", "0xab", "AB", "abc"} {
		if normalizeSerial(serial) != "ab" && normalizeSerial(serial) != "abc" {
			t.Errorf("normalizeSerial(%q) = %q", serial, normalizeSerial(serial))
		}
	}
	if normalizeSerial("0abc") != "abc" {
		t.Fatalf("normalizeSerial(0abc) = %q", normalizeSerial("0abc"))
	}
	scopes := []struct {
		name   string
		domain []string
		want   bool
	}{
		{"example.com", []string{"example.com"}, true},
		{"www.example.com", []string{"example.com"}, true},
		{"*.example.com", []string{"example.com"}, true},
		{"other.com", []string{"example.com"}, false},
		{"notexample.com", []string{"example.com"}, false},
	}
	for _, scope := range scopes {
		if got := inScope(scope.name, scope.domain); got != scope.want {
			t.Errorf("inScope(%q) = %v, want %v", scope.name, got, scope.want)
		}
	}
}
