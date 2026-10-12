package render

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/diag"
)

func TestCTFormats(t *testing.T) {
	value := false
	certificate := ct.Certificate{Fingerprint: "abc", Serial: "1", SubjectNames: []string{"a", "b", "c", "d"}, Issuer: "CA", NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), LifetimeDays: 90, Verdict100D: "ok", Revoked: &value, Source: "test"}
	document := CTDocument{SchemaVersion: "scadenza.ct/v1", Domain: "example.com", GeneratedAt: certificate.NotBefore, SourcesUsed: []string{"test"}, Certificates: []ct.Certificate{certificate}, Diagnostics: nil}
	for _, format := range []string{"json", "csv", "table"} {
		t.Run(format, func(t *testing.T) {
			var output bytes.Buffer
			if err := CT(&output, format, document); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), "abc") && format != "table" {
				t.Fatalf("output = %q", output.String())
			}
			if format == "table" && !strings.Contains(output.String(), "+1 more") {
				t.Fatalf("output = %q", output.String())
			}
		})
	}
	if err := CT(&bytes.Buffer{}, "xml", document); err == nil {
		t.Fatal("expected format error")
	}
}

func TestCTJSONMatchesPublishedRequiredFields(t *testing.T) {
	schemaData, err := os.ReadFile(filepath.Join("..", "..", "docs", "schema", "ct-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(schemaData, &schema); err != nil {
		t.Fatal(err)
	}
	document := CTDocument{SchemaVersion: "scadenza.ct/v1", Domain: "example.com", GeneratedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), SourcesUsed: []string{}, Certificates: []ct.Certificate{}, Diagnostics: []diag.Diagnostic{}}
	var output bytes.Buffer
	if err := CT(&output, "json", document); err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(output.Bytes(), &object); err != nil {
		t.Fatal(err)
	}
	for _, field := range schema.Required {
		if _, ok := object[field]; !ok {
			t.Errorf("required field %q missing", field)
		}
	}
	if len(object) != len(schema.Required) {
		t.Fatalf("unexpected top-level fields: %v", object)
	}
}
