package safefile

import (
	"errors"
	"strings"
	"testing"
)

// nestedDocument returns a YAML document with the given number of nested
// mappings. One mapping is a document that holds a single scalar.
func nestedDocument(mappings int) string {
	var builder strings.Builder
	indent := ""
	for range mappings - 1 {
		builder.WriteString(indent + "level:\n")
		indent += "  "
	}
	builder.WriteString(indent + "value: 1\n")
	return builder.String()
}

func TestDecodeYAMLReadsOneDocument(t *testing.T) {
	var value struct {
		Version int `yaml:"version"`
	}
	if err := DecodeYAML([]byte("version: 1\n"), &value); err != nil {
		t.Fatal(err)
	}
	if value.Version != 1 {
		t.Fatalf("version = %d", value.Version)
	}
}

func TestDecodeYAMLLeavesAnEmptyDocumentUnset(t *testing.T) {
	var value struct {
		Version int `yaml:"version"`
	}
	if err := DecodeYAML(nil, &value); err != nil {
		t.Fatal(err)
	}
	if value.Version != 0 {
		t.Fatalf("version = %d", value.Version)
	}
}

func TestDecodeYAMLRejectsASecondDocument(t *testing.T) {
	var value struct {
		Version int `yaml:"version"`
	}
	err := DecodeYAML([]byte("version: 1\n---\nversion: 2\n"), &value)
	if !errors.Is(err, ErrMultipleDocuments) {
		t.Fatalf("err = %v, want ErrMultipleDocuments", err)
	}
}

func TestDecodeYAMLRejectsUnknownFields(t *testing.T) {
	var value struct {
		Version int `yaml:"version"`
	}
	err := DecodeYAML([]byte("version: 1\nverbose: true\n"), &value)
	if err == nil || !strings.Contains(err.Error(), "field verbose") {
		t.Fatalf("err = %v, want an unknown-field error", err)
	}
}

func TestDecodeYAMLRejectsDeepNesting(t *testing.T) {
	var value any
	err := DecodeYAML([]byte(nestedDocument(MaxYAMLDepth+1)), &value)
	if err == nil || !strings.Contains(err.Error(), "nests deeper") {
		t.Fatalf("err = %v, want a depth error", err)
	}
	if !strings.Contains(err.Error(), "64") {
		t.Errorf("err = %v, want the limit in the message", err)
	}
}

func TestDecodeYAMLAcceptsNestingAtTheLimit(t *testing.T) {
	var value any
	if err := DecodeYAML([]byte(nestedDocument(MaxYAMLDepth)), &value); err != nil {
		t.Fatalf("err = %v, want the document to be accepted", err)
	}
}

func TestDecodeYAMLRejectsATypeError(t *testing.T) {
	var value struct {
		Version int `yaml:"version"`
	}
	err := DecodeYAML([]byte("version: \"one\"\n"), &value)
	if err == nil || !strings.Contains(err.Error(), "cannot unmarshal") {
		t.Fatalf("err = %v, want a type error", err)
	}
}
