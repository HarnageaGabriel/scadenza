package renewal

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/policy"
)

// benchEvaluationTime is the fixed instant the synthetic estate is built
// around, so a run is repeatable and no benchmark reads a clock.
var benchEvaluationTime = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

const (
	// benchOwnerCount is the number of distinct owners in a synthetic estate.
	benchOwnerCount = 200
	// benchDomainCount is the number of in-scope domains.
	benchDomainCount = 20
)

// benchSizes are the estate sizes the survey measures.
func benchSizes() []int { return []int{1000, 10000, 50000} }

// benchFingerprint derives a stable SHA-256 fingerprint from a seed string.
func benchFingerprint(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

// benchIssuances builds the Certificate Transparency corpus every certificate
// of the estate is classified against. A real scan hands the same corpus to
// every certificate, so the corpus grows with the estate.
func benchIssuances(size int) []Issuance {
	random := rand.New(rand.NewPCG(0x1cea5e11, 0x7a1e5eed))
	issuances := make([]Issuance, 0, size+size/10)
	for index := 0; index < size; index++ {
		id := strconv.Itoa(index)
		nameCount := 1 + random.IntN(5)
		names := make([]string, 0, nameCount)
		for position := 0; position < nameCount; position++ {
			names = append(names, fmt.Sprintf("svc-%s-%d.domain%02d.example", id, position, index%benchDomainCount))
		}
		notBefore := benchEvaluationTime.Add(-time.Duration(random.IntN(300)) * 24 * time.Hour)
		issuances = append(issuances, Issuance{
			Names:       names,
			NotBefore:   notBefore,
			Issuer:      "R3, E1",
			Fingerprint: benchFingerprint("ct/" + id),
			Serial:      fmt.Sprintf("%016x", random.Uint64()),
		})
		if random.IntN(10) == 0 {
			duplicate := issuances[index]
			duplicate.Fingerprint = ""
			issuances = append(issuances, duplicate)
		}
	}
	return issuances
}

// benchEstate builds the per-certificate classification inputs of an estate of
// the given size, together with the Certificate Transparency corpus every one
// of them is classified against.
func benchEstate(size int) ([]Input, []Issuance) {
	random := rand.New(rand.NewPCG(0x0b3e4c11, 0x2b7a5eed))
	issuances := benchIssuances(size)
	inputs := make([]Input, 0, size)
	for index := 0; index < size; index++ {
		id := strconv.Itoa(index)
		nameCount := 1 + random.IntN(5)
		names := make([]string, 0, nameCount)
		for position := 0; position < nameCount; position++ {
			names = append(names, fmt.Sprintf("svc-%s-%d.domain%02d.example", id, position, index%benchDomainCount))
		}
		notBefore := benchEvaluationTime.Add(-time.Duration(random.IntN(200)) * 24 * time.Hour)
		notAfter := notBefore.Add(time.Duration(30+random.IntN(340)) * 24 * time.Hour)
		input := Input{
			Names:     names,
			NotBefore: notBefore,
			NotAfter:  notAfter,
			Policy:    policy.Assess(notBefore, notAfter),
			HasCT:     true,
			HasLive:   random.IntN(2) == 0,
			CT:        issuances,
			Now:       benchEvaluationTime,
		}
		if random.IntN(3) == 0 {
			input.Manager = &Manager{
				IssuerType:     "acme",
				ACMEServer:     "https://acme-v02.api.letsencrypt.org/directory",
				Duration:       "2160h",
				RenewBefore:    "720h",
				StatusNotAfter: notAfter.Format(time.RFC3339),
				RenewalTime:    notBefore.Add(30 * 24 * time.Hour).Format(time.RFC3339),
				Ready:          "True",
			}
		}
		if random.IntN(5) == 0 {
			validityMonths := 3 + random.IntN(10)
			daysBeforeExpiry := 30
			input.KeyVaults = []KeyVault{{
				Vault:          "vault" + strconv.Itoa(index%4),
				Issuer:         "R3, E1",
				ValidityMonths: &validityMonths,
				LifetimeActions: []LifetimeAction{{
					Type:             "AutoRenew",
					DaysBeforeExpiry: &daysBeforeExpiry,
				}},
			}}
		}
		if random.IntN(4) == 0 {
			input.Secrets = []Secret{{CertificateName: "cert-" + id}}
		}
		inputs = append(inputs, input)
	}
	return inputs, issuances
}

// benchOwnerCertificates builds the per-owner workload inputs of an estate of
// the given size.
func benchOwnerCertificates(size int) []OwnerCertificate {
	random := rand.New(rand.NewPCG(0x0a0e4c11, 0x5a1e5eed))
	certificates := make([]OwnerCertificate, 0, size)
	for index := 0; index < size; index++ {
		entry := OwnerCertificate{}
		switch random.IntN(3) {
		case 0:
			entry.Mode = ModeAutomatic
		case 1:
			entry.Mode = ModeManual
		default:
			entry.Mode = ModeUnknown
		}
		switch random.IntN(4) {
		case 0:
			entry.Health = HealthDegraded
		case 1:
			entry.Health = HealthHealthy
		default:
			entry.Health = HealthUnknown
		}
		entry.Owners = append(entry.Owners, Owner{Value: fmt.Sprintf("team-%03d", index%benchOwnerCount), Source: "label"})
		if random.IntN(5) == 0 {
			entry.Owners = append(entry.Owners, Owner{Value: fmt.Sprintf("team-%03d", (index+7)%benchOwnerCount), Source: "mapping-file"})
		}
		certificates = append(certificates, entry)
	}
	return certificates
}

// BenchmarkClassify measures the renewal classification of every certificate
// of an estate against the Certificate Transparency corpus the scan collected.
func BenchmarkClassify(b *testing.B) {
	for _, size := range benchSizes() {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			if size == 50000 && os.Getenv("SCADENZA_BENCH_CLASSIFY_50000") == "" {
				b.Skip("set SCADENZA_BENCH_CLASSIFY_50000=1 to run the pathological 50k case (minutes)")
			}
			inputs, _ := benchEstate(size)
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				for _, input := range inputs {
					classification := Classify(input)
					if classification.Mode == "" {
						b.Fatal("expected a renewal mode")
					}
				}
			}
		})
	}
}

// BenchmarkSummarizeOwners measures the per-owner renewal workload summary of
// an estate.
func BenchmarkSummarizeOwners(b *testing.B) {
	for _, size := range benchSizes() {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			certificates := benchOwnerCertificates(size)
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				summaries := SummarizeOwners(certificates)
				if len(summaries) == 0 {
					b.Fatal("expected an owner summary")
				}
			}
		})
	}
}
