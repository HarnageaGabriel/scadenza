package inventory

import (
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/kube"
)

// TestCorrelateWeakJoinRequiresEqualNameSets pins the documented weak join: a
// fingerprintless cert-manager observation joins exactly one CT or live
// certificate only when the complete normalized name sets are equal and
// notAfter is exactly equal. A CT record for a.example.com and a cert-manager
// record for b.example.com with the same notAfter therefore stay separate and
// the Kubernetes entry stays unresolved, while equal name sets with the same
// notAfter join as names_and_expiry. See docs/cli/scan.md (correlation rules)
// and docs/adr/0005-kubernetes-client.md.
func TestCorrelateWeakJoinRequiresEqualNameSets(t *testing.T) {
	notAfter := date(2, time.April)
	ctRecord := ct.Certificate{
		SubjectNames: []string{"a.example.com"},
		NotAfter:     notAfter,
		Source:       "certspotter",
		DedupKey:     "one",
	}
	kubeRecord := kube.Certificate{
		DedupKey: "cert-manager/payments/api",
		Names:    []string{"b.example.com"},
		NotAfter: notAfter,
		Observations: []kube.Observation{{
			Source:   kube.SourceCertManager,
			Location: "payments/api",
		}},
	}
	matchingKubeRecord := kubeRecord
	matchingKubeRecord.Names = []string{"a.example.com"}

	tests := []struct {
		name       string
		kubeRecord kube.Certificate
		wantJoined bool
	}{
		{"different name sets stay separate", kubeRecord, false},
		{"equal name sets join", matchingKubeRecord, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			certificates, _ := Correlate(Input{
				CT:   []ct.Certificate{ctRecord},
				Kube: []kube.Certificate{test.kubeRecord},
				Now:  date(1, time.February),
			})
			if test.wantJoined {
				if len(certificates) != 1 {
					t.Fatalf("certificates = %+v", certificates)
				}
				if certificates[0].CorrelationMethod != CorrelationNamesExpiry {
					t.Fatalf("correlation_method = %q, want %q", certificates[0].CorrelationMethod, CorrelationNamesExpiry)
				}
				if len(certificates[0].Observations) != 2 {
					t.Fatalf("observations = %+v", certificates[0].Observations)
				}
				return
			}
			if len(certificates) != 2 {
				t.Fatalf("certificates = %+v", certificates)
			}
			kubernetesEntry, ctEntry := entryBySource(certificates, kube.SourceCertManager), entryBySource(certificates, SourceCertSpotter)
			if kubernetesEntry == nil || ctEntry == nil {
				t.Fatalf("expected one Kubernetes entry and one CT entry, got %+v", certificates)
			}
			if kubernetesEntry.CorrelationMethod != CorrelationUnresolved {
				t.Fatalf("kubernetes correlation_method = %q, want %q", kubernetesEntry.CorrelationMethod, CorrelationUnresolved)
			}
			if len(kubernetesEntry.Observations) != 1 || len(ctEntry.Observations) != 1 {
				t.Fatalf("observations = %+v", certificates)
			}
			if len(kubernetesEntry.Names) != 1 || kubernetesEntry.Names[0] != "b.example.com" {
				t.Fatalf("kubernetes names = %v", kubernetesEntry.Names)
			}
			if len(ctEntry.Names) != 1 || ctEntry.Names[0] != "a.example.com" {
				t.Fatalf("ct names = %v", ctEntry.Names)
			}
		})
	}
}

// entryBySource returns the entry that carries an observation of the source.
func entryBySource(certificates []Certificate, source string) *Certificate {
	for index := range certificates {
		for _, observation := range certificates[index].Observations {
			if observation.Source == source {
				return &certificates[index]
			}
		}
	}
	return nil
}
