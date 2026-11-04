package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"os"
	"runtime"
	"runtime/metrics"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/azurekv"
	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/kube"
	"github.com/HarnageaGabriel/scadenza/internal/owner"
	"github.com/HarnageaGabriel/scadenza/internal/tlsprobe"
)

// benchEvaluationTime is the fixed instant every synthetic estate is built
// around, so a run is repeatable and no benchmark reads a clock.
var benchEvaluationTime = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

const (
	// benchOwnerCount is the number of distinct owners in a synthetic estate.
	benchOwnerCount = 200
	// benchDomainCount is the number of in-scope domains.
	benchDomainCount = 20
	// benchVaultCount is the number of Key Vaults the estate spreads over.
	benchVaultCount = 4
	// benchNamespaceCount is the number of Kubernetes namespaces.
	benchNamespaceCount = 40
)

// benchIssuers are the certificate authorities a synthetic estate uses.
var benchIssuers = []string{
	"R3, E1",
	"DigiCert Global G2",
	"ISRG Root X1",
	"Sectigo RSA DV",
	"Microsoft RSA TLS CA 02",
}

// benchSizes are the estate sizes the survey measures.
func benchSizes() []int { return []int{1000, 10000, 50000} }

// benchFingerprint derives a stable SHA-256 fingerprint from a seed string, so
// the same synthetic certificate always carries the same fingerprint.
func benchFingerprint(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

// benchEstate builds a synthetic estate of size certificates. The shapes are
// the ones a large estate produces: one to five names per certificate,
// observations from Certificate Transparency, a live probe, Kubernetes and Key
// Vault, fingerprints shared across those sources, records that only a
// Certificate Transparency backend knows, and entries that cannot be
// correlated at all.
//
// The generator is seeded, so two runs build the same estate.
func benchEstate(size int) Input {
	random := rand.New(rand.NewPCG(0x5ca9e27a, 0x1f2e3d4c))

	domains := make([]string, 0, benchDomainCount)
	for index := 0; index < benchDomainCount; index++ {
		domains = append(domains, fmt.Sprintf("domain%02d.example", index))
	}
	owners := make([]owner.Owner, benchOwnerCount)
	for index := range owners {
		owners[index] = owner.Owner{
			Value:    fmt.Sprintf("team-%03d", index),
			Source:   owner.SourceLabel,
			Location: fmt.Sprintf("app-%03d", index),
		}
	}

	input := Input{
		Domains:      domains,
		RenewalModes: map[string]string{},
		Unprobed:     map[string]string{},
		Now:          benchEvaluationTime,
	}
	// A few domains carry an explicit manual renewal declaration.
	for index := 0; index < benchDomainCount; index += 5 {
		input.RenewalModes[domains[index]] = "manual"
	}

	for index := 0; index < size; index++ {
		id := strconv.Itoa(index)
		domain := domains[index%benchDomainCount]
		namespace := fmt.Sprintf("team-%02d", index%benchNamespaceCount)
		secretName := "tls-" + id

		nameCount := 1 + random.IntN(5)
		names := make([]string, 0, nameCount)
		for position := 0; position < nameCount; position++ {
			names = append(names, fmt.Sprintf("svc-%s-%d.%s", id, position, domain))
		}
		if random.IntN(10) == 0 {
			names[0] = "*." + domain
		}
		fingerprint := benchFingerprint("cert/" + id)
		serial := fmt.Sprintf("%016x", random.Uint64())
		issuer := benchIssuers[random.IntN(len(benchIssuers))]
		lifetimeDays := 30 + random.IntN(340)
		notBefore := benchEvaluationTime.Add(-time.Duration(random.IntN(200)) * 24 * time.Hour)
		notAfter := notBefore.Add(time.Duration(lifetimeDays) * 24 * time.Hour)
		ownerEntry := owners[index%benchOwnerCount]

		source := "certspotter"
		if index%3 == 0 {
			source = "crtsh"
		}
		input.CT = append(input.CT, ct.Certificate{
			Fingerprint:  fingerprint,
			Serial:       serial,
			SubjectNames: names,
			Issuer:       issuer,
			NotBefore:    notBefore,
			NotAfter:     notAfter,
			Source:       source,
			DedupKey:     "ct/" + id,
		})
		// Overlapping domain queries return the same issuance more than once.
		if random.IntN(12) == 0 {
			duplicateSource := "certspotter"
			if source == "certspotter" {
				duplicateSource = "crtsh"
			}
			input.CT = append(input.CT, ct.Certificate{
				Fingerprint:  fingerprint,
				Serial:       serial,
				SubjectNames: names,
				Issuer:       issuer,
				NotBefore:    notBefore,
				NotAfter:     notAfter,
				Source:       duplicateSource,
				DedupKey:     "ct/" + id + "/duplicate",
			})
		}
		// A Certificate Transparency record with neither a fingerprint nor a
		// serial number cannot be correlated with anything.
		if random.IntN(50) == 0 {
			input.CT = append(input.CT, ct.Certificate{
				SubjectNames: names,
				Issuer:       issuer,
				NotBefore:    notBefore,
				NotAfter:     notAfter,
				Source:       source,
				DedupKey:     "ct-unresolved/" + id,
			})
		}

		if random.IntN(100) < 55 {
			input.Live = append(input.Live, tlsprobe.Result{
				Host:        names[0],
				Port:        443,
				SNI:         names[0],
				Fingerprint: fingerprint,
				Serial:      serial,
				Names:       names,
				Issuer:      issuer,
				NotBefore:   notBefore,
				NotAfter:    notAfter,
				TLSVersion:  "TLS1.3",
				Trusted:     random.IntN(10) > 0,
			})
		}
		// A certificate that is served live but absent from Certificate
		// Transparency.
		if random.IntN(100) < 8 {
			liveOnly := benchFingerprint("live-only/" + id)
			input.Live = append(input.Live, tlsprobe.Result{
				Host:        "live-" + id + "." + domain,
				Port:        443,
				SNI:         "live-" + id + "." + domain,
				Fingerprint: liveOnly,
				Serial:      fmt.Sprintf("%016x", random.Uint64()),
				Names:       []string{"live-" + id + "." + domain},
				Issuer:      issuer,
				NotBefore:   notBefore,
				NotAfter:    notAfter,
				TLSVersion:  "TLS1.3",
				Trusted:     random.IntN(10) > 0,
			})
		}

		if random.IntN(100) < 35 {
			public := random.IntN(4) > 0
			kubeCertificate := kube.Certificate{
				Fingerprint: fingerprint,
				DedupKey:    "secret/" + namespace + "/" + secretName,
				Serial:      serial,
				Names:       names,
				Issuer:      issuer,
				NotBefore:   notBefore,
				NotAfter:    notAfter,
				Public:      &public,
				Owners:      []owner.Owner{ownerEntry},
				Observations: []kube.Observation{{
					Source:   kube.SourceSecret,
					Location: namespace + "/" + secretName,
					Detail:   "kubernetes.io/tls secret",
					Kubernetes: &kube.Kubernetes{
						Resource:    "kubernetes.io/tls",
						Namespace:   namespace,
						Name:        secretName,
						SecretName:  secretName,
						IssuerType:  "acme",
						ACMEServer:  "https://acme-v02.api.letsencrypt.org/directory",
						Duration:    "2160h",
						RenewBefore: "720h",
					},
				}},
			}
			// A quarter of the managed certificates also carry a cert-manager
			// Certificate resource.
			if random.IntN(4) == 0 {
				kubeCertificate.Observations = append(kubeCertificate.Observations, kube.Observation{
					Source:   kube.SourceCertManager,
					Location: "certificate/" + namespace + "/" + secretName,
					Detail:   "cert-manager Certificate",
					Kubernetes: &kube.Kubernetes{
						Resource:    "cert-manager.io/v1/Certificate",
						Namespace:   namespace,
						Name:        secretName,
						IssuerType:  "acme",
						ACMEServer:  "https://acme-v02.api.letsencrypt.org/directory",
						Duration:    "2160h",
						NotAfter:    notAfter.Format(time.RFC3339),
						RenewalTime: notBefore.Add(30 * 24 * time.Hour).Format(time.RFC3339),
						Ready:       "True",
					},
				})
			}
			input.Kube = append(input.Kube, kubeCertificate)
		}
		// A Secret read through the metadata client carries no certificate
		// facts, so it can only be reported as unresolved.
		if random.IntN(100) < 4 {
			input.Kube = append(input.Kube, kube.Certificate{
				DedupKey: "secret-metadata/" + namespace + "/" + secretName,
				Owners:   []owner.Owner{ownerEntry},
				Observations: []kube.Observation{{
					Source:   kube.SourceSecretMetadata,
					Location: namespace + "/" + secretName,
					Detail:   "kubernetes.io/tls Secret metadata; certificate data not read",
				}},
			})
		}
		// A Secret whose certificate could not be parsed still carries names
		// and an expiry, so correlation tries the weak names-and-expiry join.
		if random.IntN(100) < 4 {
			input.Kube = append(input.Kube, kube.Certificate{
				DedupKey:  "secret-unparsed/" + id,
				Serial:    serial,
				Names:     names,
				Issuer:    issuer,
				NotBefore: notBefore,
				NotAfter:  notAfter,
				Owners:    []owner.Owner{ownerEntry},
				Observations: []kube.Observation{{
					Source:   kube.SourceSecret,
					Location: namespace + "/" + secretName,
					Detail:   "kubernetes.io/tls secret",
				}},
			})
		}

		if random.IntN(100) < 20 {
			validityMonths := 3 + random.IntN(10)
			daysBeforeExpiry := 30
			vault := "vault" + strconv.Itoa(index%benchVaultCount)
			input.Azure = append(input.Azure, azurekv.Certificate{
				Fingerprint: fingerprint,
				Serial:      serial,
				Names:       names,
				NotBefore:   notBefore,
				NotAfter:    notAfter,
				Facts: azurekv.Facts{
					Name:                 "cert-" + id,
					Vault:                vault,
					Version:              "v" + strconv.Itoa(1+index%3),
					Issuer:               issuer,
					PolicyValidityMonths: &validityMonths,
					LifetimeActions: []azurekv.LifetimeAction{{
						Type:             "AutoRenew",
						DaysBeforeExpiry: &daysBeforeExpiry,
					}},
					Tags: map[string]string{"owner": ownerEntry.Value},
				},
				Owners: []owner.Owner{ownerEntry},
			})
		}
	}

	for index := 0; index < size/10; index++ {
		input.Errors = append(input.Errors, ProbeError{
			Host:   fmt.Sprintf("dead-%d.%s", index, domains[index%len(domains)]),
			Port:   443,
			Class:  "dns",
			Detail: "host not found",
		})
	}
	for index := 0; index < size/20; index++ {
		input.Unprobed[fmt.Sprintf("*.%s", domains[index%len(domains)])] = "wildcard"
	}
	return input
}

// benchHeapSampler polls the live heap size without stopping the world, so a
// benchmark can report the peak memory of a run without distorting it.
type benchHeapSampler struct {
	peak atomic.Uint64
	stop chan struct{}
	done chan struct{}
}

// startBenchHeapSampler starts sampling the live heap size.
func startBenchHeapSampler() *benchHeapSampler {
	sampler := &benchHeapSampler{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(sampler.done)
		samples := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
		for {
			select {
			case <-sampler.stop:
				return
			default:
			}
			metrics.Read(samples)
			value := samples[0].Value.Uint64()
			for {
				current := sampler.peak.Load()
				if value <= current || sampler.peak.CompareAndSwap(current, value) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	return sampler
}

// stopAndPeak stops the sampler and returns the peak live heap in bytes.
func (sampler *benchHeapSampler) stopAndPeak() uint64 {
	close(sampler.stop)
	<-sampler.done
	return sampler.peak.Load()
}

// BenchmarkCorrelate measures the merge entry point of a scan on a synthetic
// estate.
func BenchmarkCorrelate(b *testing.B) {
	for _, size := range benchSizes() {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			if size == 50000 && os.Getenv("SCADENZA_BENCH_CORRELATE_50000") == "" {
				b.Skip("set SCADENZA_BENCH_CORRELATE_50000=1 to run the pathological 50k case")
			}
			input := benchEstate(size)
			b.ReportAllocs()
			runtime.GC()
			sampler := startBenchHeapSampler()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				certificates, findings := Correlate(input)
				if len(certificates) == 0 || len(findings) == 0 {
					b.Fatal("expected a correlated estate")
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(sampler.stopAndPeak())/(1<<20), "peak-heap-MB")
		})
	}
}
