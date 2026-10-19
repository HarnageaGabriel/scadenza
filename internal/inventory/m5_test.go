package inventory

import (
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/azurekv"
	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/owner"
	"github.com/HarnageaGabriel/scadenza/internal/renewal"
	"github.com/HarnageaGabriel/scadenza/internal/tlsprobe"
)

func TestCorrelateAzureKeyVaultBySHA256(t *testing.T) {
	fingerprint := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	facts := azurekv.Facts{
		Name: "api", Vault: "vault.example", Version: "v1",
		NotBefore: notBefore, NotAfter: notAfter, Issuer: "DigiCert",
		LifetimeActions: []azurekv.LifetimeAction{{Type: "AutoRenew"}},
		Tags:            map[string]string{},
	}
	certificates, findings := Correlate(Input{
		Domains: []string{"example.com"},
		CT: []ct.Certificate{{
			Fingerprint: fingerprint, SubjectNames: []string{"api.example.com"},
			Issuer: "DigiCert", NotBefore: notBefore, NotAfter: notAfter,
			Source: "certspotter", DedupKey: "api",
		}},
		Azure: []azurekv.Certificate{{
			Fingerprint: fingerprint, Serial: "1", Names: []string{"api.example.com"},
			NotBefore: notBefore, NotAfter: notAfter,
			Facts:  facts,
			Owners: []owner.Owner{{Value: "team-api", Source: owner.Source("tag"), Location: "tag/scadenza.io/owner"}},
		}},
		Live: []tlsprobe.Result{{
			Host: "api.example.com", Fingerprint: fingerprint,
			Names: []string{"api.example.com"}, NotBefore: notBefore, NotAfter: notAfter, Trusted: true,
		}},
		Now: time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
	})
	if len(certificates) != 1 {
		t.Fatalf("certificates = %d, want 1", len(certificates))
	}
	got := certificates[0]
	if got.CorrelationMethod != CorrelationSHA256 {
		t.Fatalf("correlation = %s, want sha256", got.CorrelationMethod)
	}
	azureObservations := 0
	for _, observation := range got.Observations {
		if observation.Source == SourceAzureKeyVault {
			azureObservations++
			if observation.KeyVault == nil || observation.KeyVault.Version != "v1" {
				t.Fatalf("azure observation = %+v", observation)
			}
		}
	}
	if azureObservations != 1 {
		t.Fatalf("azure observations = %d, want 1", azureObservations)
	}
	if got.Owners[0].Source != owner.Source("tag") {
		t.Fatalf("owner source = %s, want tag", got.Owners[0].Source)
	}
	if got.Renewal.Mode != renewal.ModeAutomatic {
		t.Fatalf("renewal mode = %s, want automatic", got.Renewal.Mode)
	}
	if findings[0].Kind != KindMatched {
		t.Fatalf("finding = %s, want matched", findings[0].Kind)
	}
}

func TestCorrelateSelfSignedKeyVaultIsPrivate(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	certificates, _ := Correlate(Input{
		Azure: []azurekv.Certificate{{
			Fingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Names:       []string{"internal.example"}, NotBefore: notBefore, NotAfter: notAfter,
			Facts: azurekv.Facts{
				Name: "internal", Vault: "vault.example", Version: "v1",
				NotBefore: notBefore, NotAfter: notAfter, Issuer: "Self",
				LifetimeActions: []azurekv.LifetimeAction{}, Tags: map[string]string{},
			},
		}},
		Now: time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
	})
	got := certificates[0]
	if got.Public == nil || *got.Public {
		t.Fatalf("public = %v, want false", got.Public)
	}
	if got.Verdict100D != VerdictNotApplicable {
		t.Fatalf("verdict = %s, want not_applicable", got.Verdict100D)
	}
}
