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

// TestDecodeYAMLRejectsAnchorsAliasesAndMergeKeys proves the three YAML
// constructs the readers do not support are rejected, and that the error
// names the line each construct is on. An alias can expand a document
// exponentially and a merge key can bring in keys the unknown-key check never
// sees, so neither may reach the decoder.
func TestDecodeYAMLRejectsAnchorsAliasesAndMergeKeys(t *testing.T) {
	tests := []struct {
		name     string
		document string
		line     string
	}{
		{
			name:     "anchor",
			document: "version: 1\ndefaults: &defaults\n  a: 1\n",
			line:     "line 2",
		},
		{
			name:     "alias",
			document: "defaults: &defaults\n  a: 1\nuse: *defaults\n",
			line:     "line 3",
		},
		{
			name:     "merge key",
			document: "version: 1\n<<: {a: 1}\n",
			line:     "line 2",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var value any
			err := DecodeYAML([]byte(test.document), &value)
			if err == nil {
				t.Fatal("err = nil, want the construct to be rejected")
			}
			if !strings.Contains(err.Error(), test.line) {
				t.Errorf("err = %v, want the line of the construct", err)
			}
			if !strings.Contains(err.Error(), "anchors, aliases and merge keys are not supported") {
				t.Errorf("err = %v, want the message that names the rejected constructs", err)
			}
		})
	}
}

// TestDecodeYAMLReadsANormalDocument proves a document that uses none of the
// rejected constructs is decoded as before.
func TestDecodeYAMLReadsANormalDocument(t *testing.T) {
	var value struct {
		Version int      `yaml:"version"`
		Hosts   []string `yaml:"hosts"`
		Nested  struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"nested"`
	}
	document := "version: 1\nhosts:\n  - a.example.com\n  - b.example.com\nnested:\n  enabled: true\n"
	if err := DecodeYAML([]byte(document), &value); err != nil {
		t.Fatal(err)
	}
	if value.Version != 1 {
		t.Fatalf("version = %d", value.Version)
	}
	if strings.Join(value.Hosts, ",") != "a.example.com,b.example.com" {
		t.Fatalf("hosts = %v", value.Hosts)
	}
	if !value.Nested.Enabled {
		t.Fatal("nested.enabled = false")
	}
}

// TestDecodeYAMLLeavesTheValueUnsetWhenAConstructIsRejected proves a
// rejected document never reaches the value.
func TestDecodeYAMLLeavesTheValueUnsetWhenAConstructIsRejected(t *testing.T) {
	var value struct {
		Version int `yaml:"version"`
	}
	err := DecodeYAML([]byte("version: 1\ndefaults: &defaults\n  a: 1\n"), &value)
	if err == nil {
		t.Fatal("err = nil, want the anchor to be rejected")
	}
	if value.Version != 0 {
		t.Fatalf("version = %d, want the value untouched", value.Version)
	}
}
