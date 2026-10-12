package diag

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRegistry(t *testing.T) {
	if err := RegistryError(); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, entry := range List() {
		if entry.Code == "" || entry.Slug == "" || entry.Severity == "" || entry.Summary == "" || entry.Explanation == "" || entry.Remediation == "" {
			t.Fatalf("registry entry has an empty field: %#v", entry)
		}
		if seen[entry.Code] {
			t.Fatalf("duplicate registry code %s", entry.Code)
		}
		seen[entry.Code] = true
		if got, ok := Lookup(entry.Code); !ok || !cmp.Equal(got, entry) {
			t.Fatalf("Lookup(%q) = %#v, %v; want %#v, true", entry.Code, got, ok, entry)
		}
	}
}

func TestValidateRegistry(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{name: "valid", data: "schemaVersion: 1\ncodes:\n- {code: SCD-9999, slug: example, severity: info, summary: summary, explanation: explanation, remediation: remediation}\n"},
		{name: "duplicate", data: "schemaVersion: 1\ncodes:\n- &entry {code: SCD-9999, slug: example, severity: info, summary: summary, explanation: explanation, remediation: remediation}\n- *entry\n", want: true},
		{name: "bad code", data: "schemaVersion: 1\ncodes:\n- {code: BAD-1, slug: example, severity: info, summary: summary, explanation: explanation, remediation: remediation}\n", want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ValidateRegistry([]byte(test.data)) != nil; got != test.want {
				t.Fatalf("ValidateRegistry() error = %v, want error %v", got, test.want)
			}
		})
	}
}

func TestCollector(t *testing.T) {
	first, _ := Lookup("SCD-0001")
	second, _ := Lookup("SCD-0005")
	var collector Collector
	collector.Add(first)
	collector.Add(second)
	want := []Diagnostic{first, second}
	if diff := cmp.Diff(want, collector.List()); diff != "" {
		t.Fatalf("Collector.List() mismatch (-want +got):\n%s", diff)
	}
}
