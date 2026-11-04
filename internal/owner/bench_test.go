package owner

import (
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"
)

const (
	// benchOwnerCount is the number of distinct owners in a synthetic estate.
	benchOwnerCount = 200
	// benchDomainCount is the number of in-scope domains.
	benchDomainCount = 20
)

// benchSizes are the estate sizes the survey measures.
func benchSizes() []int { return []int{1000, 10000, 50000} }

// benchConfig builds an ownership configuration with one mapping per domain
// and one per namespace, the shape a large estate's ownership file has.
func benchConfig() Config {
	var document strings.Builder
	document.WriteString("labelKeys:\n  - scadenza.io/owner\ndomains:\n")
	for index := 0; index < benchOwnerCount; index++ {
		fmt.Fprintf(&document, "  domain%03d.example: team-%03d\n", index, index)
	}
	document.WriteString("namespaces:\n")
	for index := 0; index < benchDomainCount*5; index++ {
		fmt.Fprintf(&document, "  team-%02d: team-%03d\n", index, index%benchOwnerCount)
	}
	config, err := ParseConfig([]byte(document.String()))
	if err != nil {
		panic(err)
	}
	return config
}

// benchSignals builds the ownership inputs of an estate of the given size.
func benchSignals(size int) []Signals {
	random := rand.New(rand.NewPCG(0x0b3e4c11, 0x2b7a5eed))
	signals := make([]Signals, 0, size)
	for index := 0; index < size; index++ {
		id := strconv.Itoa(index)
		names := make([]string, 0, 3)
		for position := 0; position < 1+random.IntN(3); position++ {
			names = append(names, fmt.Sprintf("svc-%s-%d.domain%03d.example", id, position, index%benchOwnerCount))
		}
		signals = append(signals, Signals{
			Object:    "secret/team-" + id,
			Labels:    map[string]string{"scadenza.io/owner": fmt.Sprintf("team-%03d", index%benchOwnerCount)},
			Names:     names,
			Namespace: fmt.Sprintf("team-%02d", index%(benchDomainCount*5)),
		})
	}
	return signals
}

// BenchmarkResolve measures the ownership resolution of a large estate.
func BenchmarkResolve(b *testing.B) {
	for _, size := range benchSizes() {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			config := benchConfig()
			signals := benchSignals(size)
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				for _, signal := range signals {
					resolved := config.Resolve(signal)
					if len(resolved) == 0 {
						b.Fatal("expected a resolved owner")
					}
				}
			}
		})
	}
}
