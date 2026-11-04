package render

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand/v2"
	"runtime"
	"runtime/metrics"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/inventory"
	"github.com/HarnageaGabriel/scadenza/internal/owner"
	"github.com/HarnageaGabriel/scadenza/internal/renewal"
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

// benchDocument builds a synthetic scan document of the given size. The
// certificates carry the same shape a correlated estate has: one to five
// names, a few observations from different sources, one or two owners, and a
// renewal classification with evidence and risks.
func benchDocument(size int) ScanDocument {
	random := rand.New(rand.NewPCG(0x3e4d0c11, 0x9a1e5eed))
	certificates := make([]inventory.Certificate, 0, size)
	findings := make([]inventory.Finding, 0, size)
	for index := 0; index < size; index++ {
		id := strconv.Itoa(index)
		nameCount := 1 + random.IntN(5)
		names := make([]string, 0, nameCount)
		for position := 0; position < nameCount; position++ {
			names = append(names, fmt.Sprintf("svc-%s-%d.domain%02d.example", id, position, index%benchDomainCount))
		}
		lifetimeDays := 30 + random.IntN(340)
		notBefore := benchEvaluationTime.Add(-time.Duration(random.IntN(200)) * 24 * time.Hour)
		notAfter := notBefore.Add(time.Duration(lifetimeDays) * 24 * time.Hour)
		observationCount := 2 + random.IntN(4)
		observations := make([]inventory.Observation, 0, observationCount)
		for observation := 0; observation < observationCount; observation++ {
			source := []string{inventory.SourceCertSpotter, inventory.SourceCrtSH, inventory.SourceTLS, inventory.SourceKubeSecret, inventory.SourceAzureKeyVault}[random.IntN(5)]
			observations = append(observations, inventory.Observation{
				Source:   source,
				Location: fmt.Sprintf("location-%s-%d", id, observation),
				Detail:   "leaf presented; trusted=true",
			})
		}
		ownerEntry := owner.Owner{
			Value:    fmt.Sprintf("team-%03d", index%benchOwnerCount),
			Source:   owner.SourceLabel,
			Location: fmt.Sprintf("app-%03d", index%benchOwnerCount),
		}
		owners := []owner.Owner{ownerEntry}
		if random.IntN(5) == 0 {
			owners = append(owners, owner.Owner{
				Value:    fmt.Sprintf("team-%03d", (index+7)%benchOwnerCount),
				Source:   owner.SourceMappingFile,
				Location: "domain/domain00.example",
			})
		}
		evidence := []renewal.Evidence{
			{Source: renewal.SourceTLS, Fact: renewal.FactNoManagingController, Value: "true"},
			{Source: renewal.SourceCT, Fact: renewal.FactCTIssuances365d, Value: strconv.Itoa(random.IntN(40))},
		}
		risks := []renewal.Risk{}
		if random.IntN(4) == 0 {
			risks = append(risks, renewal.Risk{
				Kind:      renewal.KindRenewBeforeExceedsLifetime,
				Detail:    "spec.renewBefore 720h is not shorter than the issued lifetime 2160h",
				Effective: "2027-02-10T00:00:00Z",
			})
		}
		certificates = append(certificates, inventory.Certificate{
			Fingerprint:       benchFingerprint("cert/" + id),
			Serial:            fmt.Sprintf("%016x", random.Uint64()),
			Names:             names,
			Issuer:            "R3, E1",
			NotBefore:         notBefore,
			NotAfter:          notAfter,
			LifetimeDays:      lifetimeDays,
			Verdict100D:       "ok",
			CorrelationMethod: inventory.CorrelationSHA256,
			Observations:      observations,
			Owners:            owners,
			Renewal: renewal.Classification{
				Mode:     renewal.ModeAutomatic,
				Health:   renewal.HealthHealthy,
				Evidence: evidence,
				Risks:    risks,
			},
		})
		findings = append(findings, inventory.Finding{
			Kind:        inventory.KindMatched,
			Fingerprint: benchFingerprint("cert/" + id),
			Names:       names,
			Detail:      "presented by a probed host and issued in Certificate Transparency",
		})
	}
	return ScanDocument{
		SchemaVersion: "scadenza.scan/v1",
		GeneratedAt:   benchEvaluationTime.UTC(),
		Domains:       []string{"domain00.example"},
		SourcesUsed:   []string{"ct-certspotter", "ct-crtsh", "tls"},
		Certificates:  certificates,
		Findings:      findings,
		Coverage: inventory.Coverage{
			TargetsRequested: size,
			TargetsProbed:    size,
			Ratio:            1,
		},
	}
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

// BenchmarkPipelineJSON measures a full render step of a scan: the document is
// encoded into memory the way the CLI writes it, and the size of that output
// and the peak memory of the step are reported.
func BenchmarkPipelineJSON(b *testing.B) {
	for _, size := range benchSizes() {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			document := benchDocument(size)
			b.ReportAllocs()
			runtime.GC()
			sampler := startBenchHeapSampler()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				buffer := bytes.Buffer{}
				if err := Scan(&buffer, "json", document); err != nil {
					b.Fatal(err)
				}
				if buffer.Len() == 0 {
					b.Fatal("expected a JSON document")
				}
				b.ReportMetric(float64(buffer.Len()), "json-bytes")
			}
			b.StopTimer()
			b.ReportMetric(float64(sampler.stopAndPeak())/(1<<20), "peak-heap-MB")
		})
	}
}

// BenchmarkScanJSON measures the JSON rendering of a scan document.
func BenchmarkScanJSON(b *testing.B) {
	for _, size := range benchSizes() {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			document := benchDocument(size)
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if err := Scan(io.Discard, "json", document); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkScanCSV measures the CSV rendering of a scan document.
func BenchmarkScanCSV(b *testing.B) {
	for _, size := range benchSizes() {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			document := benchDocument(size)
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if err := Scan(io.Discard, "csv", document); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkScanTable measures the table rendering of a scan document.
func BenchmarkScanTable(b *testing.B) {
	for _, size := range benchSizes() {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			document := benchDocument(size)
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if err := Scan(io.Discard, "table", document); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkScanTableGroupedOwner measures the table rendering of a scan
// document grouped by owner.
func BenchmarkScanTableGroupedOwner(b *testing.B) {
	for _, size := range benchSizes() {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			document := benchDocument(size)
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if err := ScanGrouped(io.Discard, "table", document, GroupOwner); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
