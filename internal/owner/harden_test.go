package owner

import (
	"errors"
	"strings"
	"testing"

	"github.com/HarnageaGabriel/scadenza/internal/safefile"
)

func TestParseConfigAcceptsAnOwnerValueAtTheLimit(t *testing.T) {
	value := strings.Repeat("a", MaxOwnerValueLength)
	config, err := ParseConfig([]byte("domains:\n  example.com: " + value + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	owners := config.Resolve(Signals{Object: "secret/ns/name", Names: []string{"example.com"}})
	if len(owners) != 1 || owners[0].Value != value {
		t.Fatalf("owners = %+v", owners)
	}
}

func TestParseConfigRejectsALongerOwnerValue(t *testing.T) {
	value := strings.Repeat("a", MaxOwnerValueLength+1)
	_, err := ParseConfig([]byte("domains:\n  example.com: " + value + "\n"))
	if err == nil {
		t.Fatal("expected an error for a long owner value")
	}
	if !strings.Contains(err.Error(), "253") {
		t.Errorf("err = %v, want the limit in the message", err)
	}
	if strings.Contains(err.Error(), value) {
		t.Errorf("err = %v, want no owner value in the message", err)
	}
}

func TestParseConfigRejectsALongerOwnerValueInNamespaces(t *testing.T) {
	value := strings.Repeat("a", MaxOwnerValueLength+1)
	_, err := ParseConfig([]byte("namespaces:\n  payments: " + value + "\n"))
	if err == nil {
		t.Fatal("expected an error for a long owner value")
	}
}

func TestParseConfigRejectsASecondDocument(t *testing.T) {
	_, err := ParseConfig([]byte("labelKeys: [scadenza.io/owner]\n---\nlabelKeys: [scadenza.io/owner]\n"))
	if !errors.Is(err, safefile.ErrMultipleDocuments) {
		t.Fatalf("err = %v, want ErrMultipleDocuments", err)
	}
}

func TestParseConfigRejectsDeepNesting(t *testing.T) {
	var builder strings.Builder
	indent := ""
	for range 100 {
		builder.WriteString(indent + "level:\n")
		indent += "  "
	}
	builder.WriteString(indent + "value: 1\n")
	if _, err := ParseConfig([]byte(builder.String())); err == nil {
		t.Fatal("expected an error for a deeply nested document")
	}
}
