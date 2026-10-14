package render

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/diag"
	"github.com/HarnageaGabriel/scadenza/internal/inventory"
	"github.com/HarnageaGabriel/scadenza/internal/owner"
	"github.com/HarnageaGabriel/scadenza/internal/renewal"
)

func sampleScanDocument() ScanDocument {
	yes := true
	return ScanDocument{
		SchemaVersion: "scadenza.scan/v1",
		GeneratedAt:   time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		Domains:       []string{"example.com"},
		SourcesUsed:   []string{"certspotter", "tls"},
		Certificates: []inventory.Certificate{{
			Fingerprint: strings.Repeat("a", 64), Serial: "abcdef", Names: []string{"example.com", "www.example.com"},
			Issuer: "CN=Example CA", NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
			LifetimeDays: 90, Verdict100D: "ok", Public: &yes,
			Observations: []inventory.Observation{
				{Source: inventory.SourceCertSpotter, Location: "certspotter", Detail: "Certificate Transparency issuance"},
				{Source: inventory.SourceTLS, Location: "www.example.com:443", Detail: "leaf presented; trusted=true"},
			},
			Owners: []owner.Owner{{Value: "team-web", Source: owner.SourceLabel, Location: "label/scadenza.io/owner"}},
		}, {
			Fingerprint: strings.Repeat("b", 64), Serial: "1b", Names: []string{"api.payments.example.com"},
			Issuer: "CN=Payments Internal CA", NotBefore: time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC),
			LifetimeDays: 90, Verdict100D: inventory.VerdictNotApplicable, Public: nil,
			Observations: []inventory.Observation{
				{Source: inventory.SourceKubeSecret, Location: "payments/api-tls", Detail: "kubernetes.io/tls secret"},
				{Source: inventory.SourceCertManager, Location: "payments/api", Detail: "Certificate -> secret api-tls"},
			},
		}},
		Findings: []inventory.Finding{
			{Kind: inventory.KindMatched, Fingerprint: strings.Repeat("a", 64), Names: []string{"www.example.com"}, Detail: "matched"},
			{Kind: inventory.KindCTOnly, Fingerprint: strings.Repeat("b", 64), Names: []string{"shop.example.com"}, Detail: "ct only"},
			{Kind: inventory.KindLiveOnly, Fingerprint: strings.Repeat("c", 64), Names: []string{"api.example.com"}, Detail: "live only; private_or_untrusted"},
			{Kind: inventory.KindNotChecked, Fingerprint: strings.Repeat("d", 64), Names: []string{"*.example.com"}, Detail: "not checked"},
			{Kind: inventory.KindUnknown, Fingerprint: "", Names: []string{"x.example.com"}, Detail: "unknown"},
			{Kind: inventory.KindExceeds100D, Fingerprint: strings.Repeat("e", 64), Names: []string{"long.example.com"}, Detail: "exceeds"},
			{Kind: inventory.KindKubeOnly, Fingerprint: strings.Repeat("b", 64), Names: []string{"api.payments.example.com"}, Detail: "read from Kubernetes"},
		},
		Unresolved:  []inventory.Unresolved{{Name: "*.example.com", Reason: "wildcard", Detail: "wildcard"}},
		ProbeErrors: []inventory.ProbeError{{Host: "api.example.com", Port: 443, Class: "refused", Detail: "probe api.example.com:443: refused"}},
		Diagnostics: []diag.Diagnostic{},
	}
}

func TestScanJSONArraysAreNeverNull(t *testing.T) {
	document := ScanDocument{
		Certificates: []inventory.Certificate{{}},
		Findings:     []inventory.Finding{{}},
	}
	var output bytes.Buffer
	if err := Scan(&output, "json", document); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"domains", "sources_used", "certificates", "names", "observations", "owners", "findings", "unresolved", "probe_errors", "diagnostics"} {
		if strings.Contains(output.String(), `"`+field+`":null`) {
			t.Fatalf("JSON contains null %s array: %s", field, output.String())
		}
	}
}

func TestScanFormats(t *testing.T) {
	document := sampleScanDocument()
	for _, format := range []string{"json", "csv", "table"} {
		t.Run(format, func(t *testing.T) {
			var output bytes.Buffer
			if err := Scan(&output, format, document); err != nil {
				t.Fatal(err)
			}
			if format == "json" && !strings.Contains(output.String(), "scadenza.scan/v1") {
				t.Fatalf("output = %q", output.String())
			}
			if format == "table" && (!strings.Contains(output.String(), "FINDINGS") || !strings.Contains(output.String(), "live_only")) {
				t.Fatalf("output = %q", output.String())
			}
			if format == "csv" && !strings.Contains(output.String(), "fingerprint_sha256,serial,names") {
				t.Fatalf("output = %q", output.String())
			}
		})
	}
	if err := Scan(&bytes.Buffer{}, "xml", document); err == nil {
		t.Fatal("expected format error")
	}
}

type scanSchema struct {
	Required   []string `json:"required"`
	Properties struct {
		Certificates struct {
			Items struct {
				AdditionalProperties *bool    `json:"additionalProperties"`
				Required             []string `json:"required"`
				Properties           map[string]struct {
					Properties map[string]struct {
						Enum []string `json:"enum"`
					} `json:"properties"`
					Items struct {
						Properties map[string]struct {
							Enum []string `json:"enum"`
						} `json:"properties"`
					} `json:"items"`
				} `json:"properties"`
			} `json:"items"`
		} `json:"certificates"`
		Findings struct {
			Items struct {
				Required   []string `json:"required"`
				Properties struct {
					Kind struct {
						Enum []string `json:"enum"`
					} `json:"kind"`
				} `json:"properties"`
			} `json:"items"`
		} `json:"findings"`
		Unresolved struct {
			Items struct {
				Properties struct {
					Reason struct {
						Enum []string `json:"enum"`
					} `json:"reason"`
				} `json:"properties"`
			} `json:"items"`
		} `json:"unresolved"`
		ProbeErrors struct {
			Items struct {
				Properties struct {
					Class struct {
						Enum []string `json:"enum"`
					} `json:"class"`
				} `json:"properties"`
			} `json:"items"`
		} `json:"probe_errors"`
	} `json:"properties"`
}

func loadScanSchema(t *testing.T) scanSchema {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "schema", "scan-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema scanSchema
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	return schema
}

func TestScanJSONMatchesPublishedSchema(t *testing.T) {
	schema := loadScanSchema(t)
	var output bytes.Buffer
	if err := Scan(&output, "json", sampleScanDocument()); err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(output.Bytes(), &object); err != nil {
		t.Fatal(err)
	}
	for _, field := range schema.Required {
		if _, ok := object[field]; !ok {
			t.Errorf("required top-level field %q missing", field)
		}
	}
	if len(object) != len(schema.Required) {
		t.Fatalf("top-level fields = %v, schema requires %v", keys(object), schema.Required)
	}

	var document struct {
		Certificates []map[string]json.RawMessage `json:"certificates"`
		Findings     []map[string]json.RawMessage `json:"findings"`
		Unresolved   []map[string]json.RawMessage `json:"unresolved"`
		ProbeErrors  []map[string]json.RawMessage `json:"probe_errors"`
	}
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	certificate := schema.Properties.Certificates.Items
	if certificate.AdditionalProperties == nil || *certificate.AdditionalProperties {
		t.Fatal("certificate schema must set additionalProperties false")
	}
	for _, emitted := range document.Certificates {
		// Every required field must be present and no undeclared field may be
		// emitted, because the schema sets additionalProperties false. Optional
		// fields such as the owners array are present even when empty.
		for _, field := range certificate.Required {
			if _, ok := emitted[field]; !ok {
				t.Errorf("certificate missing required field %q", field)
			}
		}
		for name := range emitted {
			if _, ok := certificate.Properties[name]; !ok {
				t.Errorf("certificate emitted undeclared property %q", name)
			}
		}
		var observations []map[string]string
		if err := json.Unmarshal(emitted["observations"], &observations); err != nil {
			t.Fatalf("decode observations: %v", err)
		}
		sourceEnum := certificate.Properties["observations"].Items.Properties["source"].Enum
		for _, observation := range observations {
			if !slices.Contains(sourceEnum, observation["source"]) {
				t.Errorf("observation source %q not in enum %v", observation["source"], sourceEnum)
			}
		}
	}
	for _, finding := range document.Findings {
		for _, field := range schema.Properties.Findings.Items.Required {
			if _, ok := finding[field]; !ok {
				t.Errorf("finding missing %q", field)
			}
		}
		var kind string
		if err := json.Unmarshal(finding["kind"], &kind); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(schema.Properties.Findings.Items.Properties.Kind.Enum, kind) {
			t.Errorf("finding kind %q not in enum", kind)
		}
	}
	for _, unresolved := range document.Unresolved {
		var reason string
		if err := json.Unmarshal(unresolved["reason"], &reason); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(schema.Properties.Unresolved.Items.Properties.Reason.Enum, reason) {
			t.Errorf("unresolved reason %q not in enum", reason)
		}
	}
	for _, probeError := range document.ProbeErrors {
		var class string
		if err := json.Unmarshal(probeError["class"], &class); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(schema.Properties.ProbeErrors.Items.Properties.Class.Enum, class) {
			t.Errorf("probe error class %q not in enum", class)
		}
	}
}

func TestScanCSVFormulaInjection(t *testing.T) {
	for _, prefix := range []string{"=", "+", "-", "@", "\t", "\r"} {
		no := false
		document := ScanDocument{Certificates: []inventory.Certificate{{
			Fingerprint: "f", Serial: prefix + "1", Names: []string{prefix + "name"}, Issuer: prefix + "CA",
			Verdict100D: "ok", Public: &no,
			Observations: []inventory.Observation{{Source: inventory.SourceTLS, Location: prefix + "host:443", Detail: prefix + "detail"}},
		}}}
		var output bytes.Buffer
		if err := Scan(&output, "csv", document); err != nil {
			t.Fatal(err)
		}
		rows, err := csv.NewReader(&output).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		row := rows[1]
		for _, index := range []int{1, 2, 3, 10, 11} {
			if !strings.HasPrefix(row[index], "'"+prefix) {
				t.Errorf("prefix %q column %d = %q", prefix, index, row[index])
			}
		}
	}
}

func TestScanCSVRowPerObservation(t *testing.T) {
	yes := true
	document := ScanDocument{Certificates: []inventory.Certificate{{
		Fingerprint: strings.Repeat("a", 64), Verdict100D: "ok", Public: &yes,
		Observations: []inventory.Observation{
			{Source: inventory.SourceCertSpotter, Location: "certspotter", Detail: "ct"},
			{Source: inventory.SourceCrtSH, Location: "crtsh", Detail: "ct"},
			{Source: inventory.SourceTLS, Location: "host:443", Detail: "tls"},
		},
	}}}
	var output bytes.Buffer
	if err := Scan(&output, "csv", document); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&output).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("csv rows = %d, want 4", len(rows))
	}
}

func keys(values map[string]json.RawMessage) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	slices.Sort(result)
	return result
}

func TestScanTableStripsControlCharacters(t *testing.T) {
	yes := true
	document := ScanDocument{Certificates: []inventory.Certificate{{
		Fingerprint:  strings.Repeat("a", 64),
		Serial:       "1b",
		Names:        []string{"evil\x1b[31m.example.com", "a\nb.example.com"},
		Issuer:       "\x1b]0;pwned\x07CN=CA",
		Verdict100D:  "ok",
		Public:       &yes,
		Observations: []inventory.Observation{{Source: inventory.SourceTLS, Location: "host:443", Detail: "leaf"}},
	}}, Findings: []inventory.Finding{{
		Kind:        inventory.KindCTOnly,
		Fingerprint: strings.Repeat("a", 64),
		Names:       []string{"a\nb.example.com"},
		Detail:      "line1\nline2\x1b[0m",
	}}}
	var output bytes.Buffer
	if err := Scan(&output, "table", document); err != nil {
		t.Fatal(err)
	}
	rendered := output.String()
	for _, bad := range []string{"\x1b", "\x07", "line1\nline2"} {
		if strings.Contains(rendered, bad) {
			t.Fatalf("table output contains %q:\n%s", bad, rendered)
		}
	}
	for _, want := range []string{"evil[31m.example.com", "ab.example.com", "line1line2"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("stripped output missing %q:\n%s", want, rendered)
		}
	}
}

func TestScanTableRisksAndGrouping(t *testing.T) {
	yes := true
	document := ScanDocument{Certificates: []inventory.Certificate{
		{
			Fingerprint: strings.Repeat("a", 64), Names: []string{"api.example.com"}, Verdict100D: "ok", Public: &yes,
			Owners:  []owner.Owner{{Value: "team-web", Source: owner.SourceLabel}},
			Renewal: renewal.Classification{Mode: renewal.ModeAutomatic, Health: renewal.HealthDegraded, Risks: []renewal.Risk{{Kind: renewal.KindRenewalDegraded, Detail: "Ready=False"}}},
		},
		{
			Fingerprint: strings.Repeat("b", 64), Names: []string{"www.example.com"}, Verdict100D: "ok", Public: &yes,
			Renewal: renewal.Classification{Mode: renewal.ModeUnknown, Health: renewal.HealthUnknown},
		},
	}}
	for _, groupBy := range []string{GroupOwner, GroupNames} {
		var output bytes.Buffer
		if err := ScanGrouped(&output, "table", document, groupBy); err != nil {
			t.Fatal(err)
		}
		rendered := output.String()
		if !strings.Contains(rendered, "GROUP "+groupBy+": ") {
			t.Errorf("grouping %q missing:\n%s", groupBy, rendered)
		}
		if !strings.Contains(rendered, "MODE") || !strings.Contains(rendered, "HEALTH") {
			t.Errorf("table missing MODE/HEALTH columns:\n%s", rendered)
		}
		if !strings.Contains(rendered, "RISKS") || !strings.Contains(rendered, renewal.KindRenewalDegraded) {
			t.Errorf("table missing the risks summary:\n%s", rendered)
		}
		if groupBy == GroupOwner && !strings.Contains(rendered, "(unowned)") {
			t.Errorf("table missing the unowned group:\n%s", rendered)
		}
	}
}
