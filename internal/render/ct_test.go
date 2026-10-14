package render

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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

func TestCSVFormulaInjection(t *testing.T) {
	for _, prefix := range []string{"=", "+", "-", "@", "\t", "\r"} {
		certificate := ct.Certificate{Fingerprint: "f", Serial: prefix + "1", SubjectNames: []string{prefix + "cmd"}, Issuer: prefix + "CA", NotBefore: time.Unix(0, 0).UTC(), NotAfter: time.Unix(0, 0).UTC(), Source: "test"}
		var output bytes.Buffer
		if err := CT(&output, "csv", CTDocument{Certificates: []ct.Certificate{certificate}}); err != nil {
			t.Fatal(err)
		}
		rows, err := csv.NewReader(&output).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		row := rows[1]
		for _, index := range []int{1, 2, 3} {
			if !strings.HasPrefix(row[index], "'"+prefix) {
				t.Errorf("prefix %q column %d = %q", prefix, index, row[index])
			}
		}
	}
	if csvSafe("plain") != "plain" || csvSafe("") != "" {
		t.Fatal("safe values altered")
	}
}

func TestCTJSONArraysAreNeverNull(t *testing.T) {
	document := CTDocument{Certificates: []ct.Certificate{{}}}
	var output bytes.Buffer
	if err := CT(&output, "json", document); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"sources_used", "certificates", "subject_names", "diagnostics"} {
		if strings.Contains(output.String(), `"`+field+`":null`) {
			t.Fatalf("JSON contains null %s array: %s", field, output.String())
		}
	}
	for _, value := range []string{"\tcell", "\rcell"} {
		if got := csvSafe(value); got != "'"+value {
			t.Fatalf("csvSafe(%q) = %q", value, got)
		}
	}
}

func TestCTDiagnosticMatchesPublishedSchema(t *testing.T) {
	schemaData, err := os.ReadFile(filepath.Join("..", "..", "docs", "schema", "ct-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties struct {
			Diagnostics struct {
				Items struct {
					AdditionalProperties *bool    `json:"additionalProperties"`
					Required             []string `json:"required"`
					Properties           map[string]struct {
						Pattern string   `json:"pattern"`
						Enum    []string `json:"enum"`
					} `json:"properties"`
				} `json:"items"`
			} `json:"diagnostics"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(schemaData, &schema); err != nil {
		t.Fatal(err)
	}
	item := schema.Properties.Diagnostics.Items
	if item.AdditionalProperties == nil || *item.AdditionalProperties {
		t.Fatal("diagnostic schema must set additionalProperties false")
	}
	var output bytes.Buffer
	for _, code := range []string{"SCD-0001", "SCD-0005", "SCD-0006"} {
		value, ok := diag.Lookup(code)
		if !ok {
			t.Fatalf("missing %s", code)
		}
		output.Reset()
		if err := CT(&output, "json", CTDocument{Diagnostics: []diag.Diagnostic{value}}); err != nil {
			t.Fatal(err)
		}
		var document struct {
			Diagnostics []map[string]string `json:"diagnostics"`
		}
		if err := json.Unmarshal(output.Bytes(), &document); err != nil {
			t.Fatal(err)
		}
		emitted := document.Diagnostics[0]
		if len(emitted) != len(item.Properties) {
			t.Fatalf("emitted %d properties, schema declares %d", len(emitted), len(item.Properties))
		}
		for _, field := range item.Required {
			if emitted[field] == "" {
				t.Errorf("%s: required %q empty", code, field)
			}
		}
		for name, rule := range item.Properties {
			if _, ok := emitted[name]; !ok {
				t.Errorf("schema property %q not emitted", name)
			}
			if rule.Pattern != "" && !regexp.MustCompile(rule.Pattern).MatchString(emitted[name]) {
				t.Errorf("%s=%q violates %s", name, emitted[name], rule.Pattern)
			}
			if len(rule.Enum) > 0 && !slices.Contains(rule.Enum, emitted[name]) {
				t.Errorf("%s=%q not in enum", name, emitted[name])
			}
		}
	}
}

func TestCTTableStripsControlCharacters(t *testing.T) {
	value := false
	certificate := ct.Certificate{
		Fingerprint: "abc",
		Serial:      "1\x1b[2J",
		SubjectNames: []string{
			"evil\x1b[31m.example.com",
			"a\nb.example.com",
		},
		Issuer:       "\x1b]0;pwned\x07CN=CA",
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		LifetimeDays: 90,
		Verdict100D:  "ok",
		Revoked:      &value,
		Source:       "test",
	}
	document := CTDocument{SchemaVersion: "scadenza.ct/v1", Domain: "example.com", GeneratedAt: certificate.NotBefore, SourcesUsed: []string{"test"}, Certificates: []ct.Certificate{certificate}}
	var output bytes.Buffer
	if err := CT(&output, "table", document); err != nil {
		t.Fatal(err)
	}
	rendered := output.String()
	for _, bad := range []string{"\x1b", "\x07"} {
		if strings.Contains(rendered, bad) {
			t.Fatalf("table output contains control character %q:\n%s", bad, rendered)
		}
	}
	for _, want := range []string{"evil[31m.example.com", "ab.example.com", "1[2J", "]0;pwnedCN=CA"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("stripped output missing %q:\n%s", want, rendered)
		}
	}
}
