package diag

import (
	_ "embed"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed registry.yaml
var registryYAML []byte

var codePattern = regexp.MustCompile(`^SCD-[0-9]{4}$`)

var entries, byCode, registryErr = parseRegistry(registryYAML)

// RegistryError reports whether the embedded registry is invalid.
func RegistryError() error { return registryErr }

// List returns registry entries sorted by code.
func List() []Diagnostic {
	result := append([]Diagnostic(nil), entries...)
	return result
}

// Lookup returns the registered diagnostic for code.
func Lookup(code string) (Diagnostic, bool) {
	diagnostic, ok := byCode[code]
	return diagnostic, ok
}

// ValidateRegistry validates a registry document.
func ValidateRegistry(data []byte) error {
	_, _, err := parseRegistry(data)
	return err
}

func parseRegistry(data []byte) ([]Diagnostic, map[string]Diagnostic, error) {
	var document struct {
		SchemaVersion int          `yaml:"schemaVersion"`
		Codes         []Diagnostic `yaml:"codes"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, nil, fmt.Errorf("decode registry: %w", err)
	}
	if document.SchemaVersion != 1 {
		return nil, nil, fmt.Errorf("schemaVersion = %d, want 1", document.SchemaVersion)
	}
	if len(document.Codes) == 0 {
		return nil, nil, fmt.Errorf("codes is empty")
	}
	index := make(map[string]Diagnostic, len(document.Codes))
	for position, diagnostic := range document.Codes {
		if err := validate(diagnostic); err != nil {
			return nil, nil, fmt.Errorf("codes[%d]: %w", position, err)
		}
		if _, exists := index[diagnostic.Code]; exists {
			return nil, nil, fmt.Errorf("duplicate code %s", diagnostic.Code)
		}
		index[diagnostic.Code] = diagnostic
	}
	sort.Slice(document.Codes, func(i, j int) bool { return document.Codes[i].Code < document.Codes[j].Code })
	return document.Codes, index, nil
}

func validate(d Diagnostic) error {
	fields := map[string]string{
		"code": d.Code, "slug": d.Slug, "severity": string(d.Severity),
		"summary": d.Summary, "explanation": d.Explanation, "remediation": d.Remediation,
	}
	for name, value := range fields {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if !codePattern.MatchString(d.Code) {
		return fmt.Errorf("invalid code %q", d.Code)
	}
	if d.Severity != SeverityError && d.Severity != SeverityWarning && d.Severity != SeverityInfo {
		return fmt.Errorf("%s has invalid severity %q", d.Code, d.Severity)
	}
	return nil
}
