package inventory

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/kube"
	"github.com/HarnageaGabriel/scadenza/internal/owner"
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
			name:      "san of another host is not observed",
			domains:   []string{"example.com"},
			ct:        []ct.Certificate{{Fingerprint: "dd", SubjectNames: []string{"www.example.com"}, Issuer: "CN=CA", NotBefore: date(1, time.January), NotAfter: date(2, time.April), Source: "certspotter", DedupKey: "11"}},
			live:      []tlsprobe.Result{{Host: "example.com", Port: 443, Fingerprint: "ee", Names: []string{"example.com", "www.example.com"}, Issuer: "CN=Other", NotBefore: date(1, time.January), NotAfter: date(2, time.April), Trusted: true}},
			wantKinds: []string{KindLiveOnly, KindNotChecked},
		},
		{
			name:      "unknown without fingerprint or serial",
			domains:   []string{"example.com"},
			ct:        []ct.Certificate{{SubjectNames: []string{"x.example.com"}, Issuer: "CN=CA", NotBefore: date(1, time.January), NotAfter: date(2, time.April), Source: "crtsh", DedupKey: "6"}},
			wantKinds: []string{KindUnknown},
		},
		{
			// An expired record that also lacks a fingerprint and serial is
			// unknown, not not_checked: the correlation check precedes the
			// deferral rules. See docs/cli/scan.md.
			name:      "unknown precedes expired deferral",
			domains:   []string{"example.com"},
			ct:        []ct.Certificate{{SubjectNames: []string{"old.example.com"}, Issuer: "CN=CA", NotBefore: date(1, time.January), NotAfter: date(5, time.January), Source: "crtsh", DedupKey: "12"}},
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

func kubeFacts(namespace, name string) *kube.Kubernetes {
	return &kube.Kubernetes{Resource: "kubernetes.io/tls", Namespace: namespace, Name: name}
}

func TestCorrelateKubernetesOnly(t *testing.T) {
	now := date(1, time.February)
	input := Input{
		Now: now,
		Kube: []kube.Certificate{{
			Fingerprint: "ee",
			DedupKey:    "secret/payments/db",
			Serial:      "0a",
			Names:       []string{"db.payments.svc"},
			Issuer:      "CN=Kube CA",
			NotBefore:   date(1, time.January),
			NotAfter:    date(1, time.April),
			Owners:      []owner.Owner{{Value: "team-pay", Source: owner.SourceLabel, Location: "secret/payments/db"}},
			Observations: []kube.Observation{{
				Source:     kube.SourceSecret,
				Location:   "payments/db",
				Detail:     "kubernetes.io/tls secret",
				Kubernetes: kubeFacts("payments", "db"),
			}},
		}},
	}
	certificates, findings := Correlate(input)
	again, againFindings := Correlate(input)
	if diff := cmp.Diff(certificates, again); diff != "" {
		t.Fatalf("non-deterministic certificates (-first +second):\n%s", diff)
	}
	if diff := cmp.Diff(findings, againFindings); diff != "" {
		t.Fatalf("non-deterministic findings (-first +second):\n%s", diff)
	}
	if len(certificates) != 1 {
		t.Fatalf("certificates = %+v", certificates)
	}
	certificate := certificates[0]
	if certificate.LifetimeDays != 90 {
		t.Fatalf("lifetime = %d", certificate.LifetimeDays)
	}
	if certificate.Verdict100D != VerdictNotApplicable {
		t.Fatalf("verdict = %q, want %q", certificate.Verdict100D, VerdictNotApplicable)
	}
	if certificate.Public != nil {
		t.Fatalf("public = %v, want unknown", *certificate.Public)
	}
	if len(certificate.Owners) != 1 || certificate.Owners[0].Source != owner.SourceLabel {
		t.Fatalf("owners = %+v", certificate.Owners)
	}
	if certificate.Observations[0].Kubernetes == nil {
		t.Fatalf("kubernetes facts missing: %+v", certificate.Observations)
	}
	if len(findings) != 1 || findings[0].Kind != KindKubeOnly {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestCorrelateKubernetesPublicVerdict(t *testing.T) {
	public := true
	certificates, findings := Correlate(Input{
		Now: date(1, time.February),
		Kube: []kube.Certificate{{
			Fingerprint: "ff",
			DedupKey:    "secret/payments/public",
			Names:       []string{"public.example.com"},
			NotBefore:   date(1, time.January),
			NotAfter:    date(1, time.April),
			Public:      &public,
			Observations: []kube.Observation{{
				Source:     kube.SourceSecret,
				Location:   "payments/public",
				Detail:     "kubernetes.io/tls secret",
				Kubernetes: kubeFacts("payments", "public"),
			}},
		}},
	})
	if len(certificates) != 1 || certificates[0].Verdict100D != "ok" {
		t.Fatalf("certificates = %+v", certificates)
	}
	if certificates[0].Public == nil || !*certificates[0].Public {
		t.Fatalf("public = %+v", certificates[0].Public)
	}
	if len(findings) != 1 || findings[0].Kind != KindKubeOnly {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestCorrelateKubernetesCorrelatesWithCTAndLive(t *testing.T) {
	live := tlsprobe.Result{
		Host: "www.example.com", Port: 443, Fingerprint: "aa", Names: []string{"www.example.com"},
		Issuer: "CN=CA", NotBefore: date(1, time.January), NotAfter: date(1, time.April), Trusted: true,
	}
	certificates, findings := Correlate(Input{
		Domains: []string{"example.com"},
		Now:     date(1, time.February),
		CT: []ct.Certificate{{
			Fingerprint: "aa", SubjectNames: []string{"example.com", "www.example.com"}, Issuer: "CN=CA",
			NotBefore: date(1, time.January), NotAfter: date(1, time.April), Source: "certspotter", DedupKey: "1",
		}},
		Live: []tlsprobe.Result{live},
		Kube: []kube.Certificate{{
			Fingerprint: "aa",
			DedupKey:    "secret/web/tls",
			Names:       []string{"example.com"},
			NotBefore:   date(1, time.January),
			NotAfter:    date(1, time.April),
			Owners:      []owner.Owner{{Value: "team-web", Source: owner.SourceMappingFile, Location: "domain/example.com"}},
			Observations: []kube.Observation{{
				Source:     kube.SourceSecret,
				Location:   "web/tls",
				Detail:     "kubernetes.io/tls secret",
				Kubernetes: kubeFacts("web", "tls"),
			}},
		}},
	})
	if len(certificates) != 1 {
		t.Fatalf("certificates = %+v", certificates)
	}
	certificate := certificates[0]
	if len(certificate.Observations) != 3 {
		t.Fatalf("observations = %+v", certificate.Observations)
	}
	if len(certificate.Owners) != 1 || certificate.Owners[0].Value != "team-web" {
		t.Fatalf("owners = %+v", certificate.Owners)
	}
	if certificate.Verdict100D != "ok" || certificate.Public == nil || !*certificate.Public {
		t.Fatalf("verdict=%q public=%v", certificate.Verdict100D, certificate.Public)
	}
	if len(findings) != 1 || findings[0].Kind != KindMatched {
		t.Fatalf("findings = %+v", findings)
	}
}
