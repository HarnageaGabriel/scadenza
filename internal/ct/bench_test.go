package ct

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"strconv"
	"testing"
	"time"
)

// benchEvaluationTime is the fixed instant the synthetic corpus is built
// around, so a run is repeatable and no benchmark reads a clock.
var benchEvaluationTime = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

// benchSizes are the corpus sizes the survey measures.
func benchSizes() []int { return []int{1000, 10000, 50000} }

// benchCorpus builds a synthetic Certificate Transparency corpus of the given
// size. Every record carries one to five subject names, and a tenth of the
// records repeat a fingerprint, the way overlapping domain queries do.
func benchCorpus(size int) []Certificate {
	random := rand.New(rand.NewPCG(0x0c7c0f11, 0x5eed1234))
	corpus := make([]Certificate, 0, size+size/10)
	for index := 0; index < size; index++ {
		id := strconv.Itoa(index)
		nameCount := 1 + random.IntN(5)
		names := make([]string, 0, nameCount)
		for position := 0; position < nameCount; position++ {
			names = append(names, fmt.Sprintf("svc-%s-%d.domain%02d.example", id, position, index%20))
		}
		lifetimeDays := 30 + random.IntN(340)
		notBefore := benchEvaluationTime.Add(-time.Duration(random.IntN(200)) * 24 * time.Hour)
		corpus = append(corpus, Certificate{
			Fingerprint:  benchFingerprint("ct/" + id),
			Serial:       fmt.Sprintf("%016x", random.Uint64()),
			SubjectNames: names,
			Issuer:       "R3, E1",
			NotBefore:    notBefore,
			NotAfter:     notBefore.Add(time.Duration(lifetimeDays) * 24 * time.Hour),
			Source:       "certspotter",
			DedupKey:     "ct/" + id,
		})
		if random.IntN(10) == 0 {
			duplicate := corpus[index]
			duplicate.Source = "crtsh"
			duplicate.DedupKey = "ct/" + id + "/duplicate"
			corpus = append(corpus, duplicate)
		}
	}
	return corpus
}

// benchFingerprint derives a stable SHA-256 fingerprint from a seed string.
func benchFingerprint(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

// BenchmarkFinalize measures the deduplication, classification and sorting of
// a large Certificate Transparency corpus.
func BenchmarkFinalize(b *testing.B) {
	for _, size := range benchSizes() {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			corpus := benchCorpus(size)
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				finalized, truncated := Finalize(corpus, benchEvaluationTime, false, 0)
				if len(finalized) == 0 {
					b.Fatal("expected a finalized corpus")
				}
				if truncated {
					b.Fatal("expected no truncation")
				}
			}
		})
	}
}
