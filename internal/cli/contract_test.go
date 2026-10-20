package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/azurekv"
	"github.com/HarnageaGabriel/scadenza/internal/tlsprobe"
)

// The project publishes JSON Schema (draft 2020-12) files in docs/schema and
// validates every end-to-end scenario against them here. The validator below
// implements exactly the keywords those schemas use. ADR 0007 records that a
// full third-party validator (for example
// github.com/santhosh-tekuri/jsonschema) should replace it once the module can
// be fetched from the proxy; it cannot be added in this offline environment.

func TestContractSchemasValidateScenarios(t *testing.T) {
	scenarios := []struct {
		name   string
		schema string
		run    func(t *testing.T) []byte
	}{
		{"ct success", "ct-v1.schema.json", func(t *testing.T) []byte {
			server := certSpotterServer(t, certSpotterOne)
			var stdout, stderr bytes.Buffer
			if code := execute(context.Background(), []string{"ct", "example.com", "--source", "certspotter", "--format", "json"}, &stdout, &stderr, testCTDependencies(server.URL, server.URL)); code != ExitOK {
				t.Fatalf("ct exit = %d; stderr=%s", code, stderr.String())
			}
			return stdout.Bytes()
		}},
		{"scan success", "scan-v1.schema.json", func(t *testing.T) []byte {
			server := certSpotterServer(t, ctOnlyFixture())
			var stdout, stderr bytes.Buffer
			if code := execute(context.Background(), []string{"scan", "--domain", "example.com", "--source", "certspotter", "--format", "json"}, &stdout, &stderr, scanDependencies(server.URL, ctOnlyProber())); code != ExitOK {
				t.Fatalf("scan exit = %d; stderr=%s", code, stderr.String())
			}
			return stdout.Bytes()
		}},
		{"scan partial failure", "scan-v1.schema.json", func(t *testing.T) []byte {
			server := certSpotterServer(t, scanCTFixture())
			var stdout, stderr bytes.Buffer
			execute(context.Background(), []string{"scan", "--domain", "example.com", "--source", "certspotter", "--format", "json"}, &stdout, &stderr, scanDependencies(server.URL, goldenProber()))
			return stdout.Bytes()
		}},
		{"scan all sources failed", "scan-v1.schema.json", func(_ *testing.T) []byte {
			var stdout bytes.Buffer
			execute(context.Background(), []string{"scan", "--domain", "example.com", "--source", "certspotter", "--format", "json"}, &stdout, &bytes.Buffer{}, scanDependencies("http://127.0.0.1:1", goldenProber()))
			return stdout.Bytes()
		}},
		{"scan strict with default sources", "scan-v1.schema.json", func(t *testing.T) []byte {
			body := fmt.Sprintf(`[{"id":"1","cert_sha256":"%s","dns_names":["example.com"],"issuer":{"name":"CN=Example Root"},"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","revoked":false}]`, strings.Repeat("a", 64))
			server := certSpotterServer(t, body)
			prober := fakeProber{results: map[string]tlsprobe.Result{
				"example.com:443": {Fingerprint: strings.Repeat("a", 64), Names: []string{"example.com"}, Issuer: "CN=Example Root", NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), Trusted: true},
			}}
			var stdout, stderr bytes.Buffer
			if code := execute(context.Background(), []string{"scan", "--domain", "example.com", "--fail-on", "none", "--strict", "--format", "json"}, &stdout, &stderr, scanDependencies(server.URL, prober)); code != ExitOK {
				t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
			}
			return stdout.Bytes()
		}},
		{"scan strict", "scan-v1.schema.json", func(t *testing.T) []byte {
			server := certSpotterServer(t, scanCTFixture())
			var stdout bytes.Buffer
			execute(context.Background(), []string{"scan", "--domain", "example.com", "--source", "certspotter", "--fail-on", "none", "--strict", "--format", "json"}, &stdout, &bytes.Buffer{}, scanDependencies(server.URL, goldenProber()))
			return stdout.Bytes()
		}},
		{"scan kube", "scan-v1.schema.json", func(t *testing.T) []byte {
			var stdout bytes.Buffer
			if code := execute(context.Background(), []string{"scan", "--kube", "--format", "json"}, &stdout, &bytes.Buffer{}, scanKubeDependencies("x", fakeProber{}, fakeKubeSource{result: kubeFixture()}, nil)); code != ExitOK {
				t.Fatalf("kube scan exit = %d", code)
			}
			return stdout.Bytes()
		}},
		{"scan kube secrets", "scan-v1.schema.json", func(t *testing.T) []byte {
			var stdout bytes.Buffer
			if code := execute(context.Background(), []string{"scan", "--kube", "--kube-secrets", "--format", "json"}, &stdout, &bytes.Buffer{}, scanKubeDependencies("x", fakeProber{}, fakeKubeSource{result: kubeFixture()}, nil)); code != ExitOK {
				t.Fatalf("kube scan exit = %d", code)
			}
			return stdout.Bytes()
		}},
		{"scan azure empty version and action type", "scan-v1.schema.json", func(t *testing.T) []byte {
			notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			notAfter := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
			stub := azureSourceStub{certificates: []azurekv.Certificate{{
				Fingerprint: strings.Repeat("f", 64), Names: []string{"vault.example"}, NotBefore: notBefore, NotAfter: notAfter,
				Facts: azurekv.Facts{
					Name: "versionless", Vault: "demo.vault.azure.net", Version: "", NotBefore: notBefore,
					NotAfter: notAfter, Issuer: "Unknown", LifetimeActions: []azurekv.LifetimeAction{{Type: ""}}, Tags: map[string]string{},
				},
			}}}
			dependencies := scanDependencies("http://127.0.0.1:1", fakeProber{})
			dependencies.loadAzure = func(azurekv.LoadOptions) (azurekv.Source, error) { return stub, nil }
			var stdout, stderr bytes.Buffer
			if code := execute(context.Background(), []string{"scan", "--azure-keyvault", "https://demo.vault.azure.net", "--format", "json"}, &stdout, &stderr, dependencies); code != ExitOK {
				t.Fatalf("azure scan exit = %d; stderr=%s", code, stderr.String())
			}
			return stdout.Bytes()
		}},
		{"scan blocked address probe error", "scan-v1.schema.json", func(t *testing.T) []byte {
			// A Certificate Transparency derived host that resolves to the
			// loopback address is never dialed; the refusal is a probe error
			// with the blocked-address class.
			server := certSpotterServer(t, blockedAddressFixture())
			prober := &tlsprobe.Prober{Timeout: 3 * time.Second, Dialer: &recordingDialer{}, Resolver: fakeResolver{addresses: map[string]string{
				"example.com":          "192.0.2.1",
				"loopback.example.com": "127.0.0.1",
			}}}
			var stdout, stderr bytes.Buffer
			execute(context.Background(), []string{"scan", "--domain", "example.com", "--source", "certspotter", "--format", "json"}, &stdout, &stderr, scanDependencies(server.URL, prober))
			if !strings.Contains(stdout.String(), `"class":"blocked-address"`) {
				t.Fatalf("no blocked-address probe error: %s", stdout.String())
			}
			return stdout.Bytes()
		}},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			output := scenario.run(t)
			schema := loadSchema(t, scenario.schema)
			var document any
			if err := json.Unmarshal(output, &document); err != nil {
				t.Fatalf("decode output: %v\n%s", err, output)
			}
			validateAgainstSchema(t, "$", schema, document)
		})
	}
}

// blockedAddressFixture is one Certificate Transparency record whose name
// resolves to a loopback address.
func blockedAddressFixture() string {
	return fmt.Sprintf(`[{"id":"1","cert_sha256":"%s","dns_names":["loopback.example.com"],"issuer":{"name":"CN=Example Root"},"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","revoked":false}]`, strings.Repeat("a", 64))
}

func TestSchemaValidatorRejectsNullArrays(t *testing.T) {
	scan := loadSchema(t, "scan-v1.schema.json")
	properties := scan["properties"].(map[string]any)
	coverage := properties["coverage"].(map[string]any)["properties"].(map[string]any)
	cases := []struct {
		name   string
		schema map[string]any
	}{
		{"certificates", properties["certificates"].(map[string]any)},
		{"sources", coverage["sources"].(map[string]any)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if matchesType(test.schema["type"], nil) {
				t.Fatalf("null unexpectedly matches schema type %v", test.schema["type"])
			}
		})
	}
}

func loadSchema(t *testing.T, name string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "schema", name))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	return schema
}

func validateAgainstSchema(t *testing.T, path string, schema map[string]any, value any) {
	t.Helper()
	if schema == nil {
		return
	}
	if enum, ok := schema["enum"].([]any); ok && !containsValue(enum, value) {
		t.Errorf("%s: %v is not one of %v", path, value, enum)
	}
	if constant, ok := schema["const"]; ok && !valuesEqual(constant, value) {
		t.Errorf("%s: %v != const %v", path, value, constant)
	}
	if kinds, ok := schema["type"]; ok && !matchesType(kinds, value) {
		t.Errorf("%s: %v does not match type %v", path, value, kinds)
	}
	switch typed := value.(type) {
	case map[string]any:
		properties, _ := schema["properties"].(map[string]any)
		for _, name := range asStrings(schema["required"]) {
			if _, ok := typed[name]; !ok {
				t.Errorf("%s: missing required property %q", path, name)
			}
		}
		if additional, ok := schema["additionalProperties"].(bool); ok && !additional {
			for name := range typed {
				if _, declared := properties[name]; !declared {
					t.Errorf("%s: undeclared property %q", path, name)
				}
			}
		}
		for name, child := range typed {
			if childSchema, ok := properties[name].(map[string]any); ok {
				validateAgainstSchema(t, path+"."+name, childSchema, child)
			}
		}
	case []any:
		if itemSchema, ok := schema["items"].(map[string]any); ok {
			for index, item := range typed {
				validateAgainstSchema(t, fmt.Sprintf("%s[%d]", path, index), itemSchema, item)
			}
		}
	case string:
		if pattern, ok := schema["pattern"].(string); ok && !matchesPattern(pattern, typed) {
			t.Errorf("%s: %q does not match %q", path, typed, pattern)
		}
		if minimum, ok := numberKeyword(schema, "minLength"); ok && float64(len(typed)) < minimum {
			t.Errorf("%s: %q is shorter than %v", path, typed, minimum)
		}
	case float64:
		if minimum, ok := numberKeyword(schema, "minimum"); ok && typed < minimum {
			t.Errorf("%s: %v < minimum %v", path, typed, minimum)
		}
		if maximum, ok := numberKeyword(schema, "maximum"); ok && typed > maximum {
			t.Errorf("%s: %v > maximum %v", path, typed, maximum)
		}
	}
}

func matchesType(kinds any, value any) bool {
	for _, kind := range asStrings(kinds) {
		switch kind {
		case "object":
			if _, ok := value.(map[string]any); ok {
				return true
			}
		case "array":
			if _, ok := value.([]any); ok {
				return true
			}
		case "string":
			if _, ok := value.(string); ok {
				return true
			}
		case "boolean":
			if _, ok := value.(bool); ok {
				return true
			}
		case "number":
			if _, ok := value.(float64); ok {
				return true
			}
		case "integer":
			if number, ok := value.(float64); ok && number == float64(int64(number)) {
				return true
			}
		case "null":
			if value == nil {
				return true
			}
		}
	}
	return false
}

func asStrings(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok {
				result = append(result, text)
			}
		}
		return result
	}
	return nil
}

func containsValue(values []any, value any) bool {
	for _, candidate := range values {
		if valuesEqual(candidate, value) {
			return true
		}
	}
	return false
}

func valuesEqual(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}

func numberKeyword(schema map[string]any, name string) (float64, bool) {
	value, ok := schema[name].(float64)
	return value, ok
}

func matchesPattern(pattern, value string) bool {
	ok, err := regexp.MatchString(pattern, value)
	if err != nil {
		return true
	}
	return ok
}
