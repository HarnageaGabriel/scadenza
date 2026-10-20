package owner

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestResolveMatchesNamespaceCaseAndSpaceInsensitively pins the namespace
// mapping promise: the object's namespace is matched against the ownership
// file without regard to case or surrounding spaces, so a namespace spelled
// "Payments" still resolves the owner declared for "payments".
func TestResolveMatchesNamespaceCaseAndSpaceInsensitively(t *testing.T) {
	config := mustConfig(t, "namespaces:\n  payments: team-pay\n")
	for _, namespace := range []string{"payments", "Payments", "PAYMENTS", " payments ", "  Payments  "} {
		t.Run(namespace, func(t *testing.T) {
			owners := config.Resolve(Signals{Object: "secret/payments/db", Namespace: namespace})
			want := []Owner{{Value: "team-pay", Source: SourceMappingFile, Location: "namespace/" + namespace}}
			if diff := cmp.Diff(want, owners); diff != "" {
				t.Fatalf("Resolve(-want +got):\n%s", diff)
			}
		})
	}
}

// TestResolveBreaksEqualLengthDomainTiesLexicographically pins the domain
// mapping promise: when two mapping entries cover a certificate name equally
// well, the lexicographically smaller domain wins, so the reported owner
// never depends on the order the names or the mapping file happen to be read
// in.
func TestResolveBreaksEqualLengthDomainTiesLexicographically(t *testing.T) {
	config := mustConfig(t, "domains:\n  a.example.com: team-a\n  b.example.com: team-b\n")
	for _, names := range [][]string{
		{"b.example.com", "a.example.com"},
		{"a.example.com", "b.example.com"},
	} {
		t.Run(strings.Join(names, ","), func(t *testing.T) {
			owners := config.Resolve(Signals{Object: "secret/ns/name", Names: names})
			want := []Owner{{Value: "team-a", Source: SourceMappingFile, Location: "domain/a.example.com"}}
			if diff := cmp.Diff(want, owners); diff != "" {
				t.Fatalf("Resolve(-want +got):\n%s", diff)
			}
		})
	}
}
