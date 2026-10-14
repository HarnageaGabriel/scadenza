package owner

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func mustConfig(t *testing.T, document string) Config {
	t.Helper()
	config, err := ParseConfig([]byte(document))
	if err != nil {
		t.Fatalf("ParseConfig(%q): %v", document, err)
	}
	return config
}

func TestParseConfigDefaults(t *testing.T) {
	for _, document := range []string{"", "\n", "# comment\n"} {
		config := mustConfig(t, document)
		if diff := cmp.Diff([]string{"scadenza.io/owner"}, config.LabelKeys()); diff != "" {
			t.Fatalf("default label keys (-want +got):\n%s", diff)
		}
	}
}

func TestParseConfigNormalization(t *testing.T) {
	config := mustConfig(t, `
labelKeys:
  - " scadenza.io/owner "
  - "scadenza.io/owner"
  - "app.kubernetes.io/managed-by"
  - ""
domains:
  "EXAMPLE.com.": team-web
  "*.example.org": team-edge
  "empty.example.net": ""
namespaces:
  "Payments": team-pay
  "empty": ""
`)
	if diff := cmp.Diff([]string{"scadenza.io/owner"}, config.LabelKeys()); diff != "" {
		t.Fatalf("label keys (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(map[string]string{"example.com": "team-web", "example.org": "team-edge"}, config.domains); diff != "" {
		t.Fatalf("domains (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(map[string]string{"payments": "team-pay"}, config.namespaces); diff != "" {
		t.Fatalf("namespaces (-want +got):\n%s", diff)
	}
}

func TestParseConfigRejectsUnknownFieldsAndTypes(t *testing.T) {
	for name, document := range map[string]string{
		"unknown field": "owners: {example.com: team}\n",
		"wrong type":    "labelKeys: scadenza.io/owner\n",
		"broken yaml":   "domains: [\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(document)); err == nil {
				t.Fatalf("ParseConfig(%q) = nil error", document)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	config := mustConfig(t, `
labelKeys:
  - scadenza.io/owner
  - platform.io/team
domains:
  example.com: team-web
  eu.example.com: team-eu
namespaces:
  payments: team-pay
`)
	empty := mustConfig(t, "")
	tests := []struct {
		name     string
		config   Config
		signals  Signals
		expected []Owner
	}{
		{
			name:    "label match",
			config:  config,
			signals: Signals{Object: "secret/payments/db", Labels: map[string]string{"scadenza.io/owner": "team-db"}},
			expected: []Owner{
				{Value: "team-db", Source: SourceLabel, Location: "secret/payments/db"},
			},
		},
		{
			name:    "annotation match",
			config:  config,
			signals: Signals{Object: "secret/payments/db", Annotations: map[string]string{"scadenza.io/owner": "team-db"}},
			expected: []Owner{
				{Value: "team-db", Source: SourceAnnotation, Location: "secret/payments/db"},
			},
		},
		{
			name:   "label and annotation both count",
			config: config,
			signals: Signals{
				Object:      "secret/payments/db",
				Labels:      map[string]string{"platform.io/team": "team-db"},
				Annotations: map[string]string{"scadenza.io/owner": "team-db"},
			},
			expected: []Owner{
				{Value: "team-db", Source: SourceAnnotation, Location: "secret/payments/db"},
				{Value: "team-db", Source: SourceLabel, Location: "secret/payments/db"},
			},
		},
		{
			name:   "namespace label",
			config: config,
			signals: Signals{
				Object:          "secret/payments/db",
				Namespace:       "payments",
				NamespaceLabels: map[string]string{"scadenza.io/owner": "team-pay"},
			},
			expected: []Owner{
				{Value: "team-pay", Source: SourceMappingFile, Location: "namespace/payments"},
				{Value: "team-pay", Source: SourceNamespaceLabel, Location: "namespace/payments"},
			},
		},
		{
			name:   "namespace annotation",
			config: config,
			signals: Signals{
				Object:               "secret/payments/db",
				Namespace:            "payments",
				NamespaceAnnotations: map[string]string{"scadenza.io/owner": "team-pay"},
			},
			expected: []Owner{
				{Value: "team-pay", Source: SourceMappingFile, Location: "namespace/payments"},
				{Value: "team-pay", Source: SourceNamespaceAnnotation, Location: "namespace/payments"},
			},
		},
		{
			name:     "namespace mapping file",
			config:   config,
			signals:  Signals{Object: "secret/payments/db", Namespace: "payments"},
			expected: []Owner{{Value: "team-pay", Source: SourceMappingFile, Location: "namespace/payments"}},
		},
		{
			name:     "domain mapping exact",
			config:   config,
			signals:  Signals{Object: "secret/payments/db", Names: []string{"example.com"}},
			expected: []Owner{{Value: "team-web", Source: SourceMappingFile, Location: "domain/example.com"}},
		},
		{
			name:     "domain mapping longest suffix wins",
			config:   config,
			signals:  Signals{Object: "secret/payments/db", Names: []string{"api.eu.example.com"}},
			expected: []Owner{{Value: "team-eu", Source: SourceMappingFile, Location: "domain/eu.example.com"}},
		},
		{
			name:    "managed-by is never an owner",
			config:  mustConfig(t, "labelKeys: [app.kubernetes.io/managed-by]\n"),
			signals: Signals{Object: "secret/payments/db", Labels: map[string]string{"app.kubernetes.io/managed-by": "cert-manager"}},
		},
		{
			name:    "empty value is not an owner",
			config:  config,
			signals: Signals{Object: "secret/payments/db", Labels: map[string]string{"scadenza.io/owner": "   "}},
		},
		{
			name:    "no signals yields no owner",
			config:  config,
			signals: Signals{Object: "secret/payments/db", Namespace: "other", Names: []string{"other.example.net"}},
		},
		{
			name:    "default config has no mappings",
			config:  empty,
			signals: Signals{Object: "secret/payments/db", Namespace: "payments", Names: []string{"example.com"}},
		},
		{
			name:    "wildcard name maps by base domain",
			config:  config,
			signals: Signals{Object: "certificate/payments/db", Names: []string{"*.example.com"}},
			expected: []Owner{
				{Value: "team-web", Source: SourceMappingFile, Location: "domain/example.com"},
			},
		},
		{
			name:   "every rule at once",
			config: config,
			signals: Signals{
				Object:          "certificate/payments/db",
				Labels:          map[string]string{"scadenza.io/owner": "team-db"},
				Namespace:       "payments",
				NamespaceLabels: map[string]string{"scadenza.io/owner": "team-ns"},
				Names:           []string{"db.example.com"},
			},
			expected: []Owner{
				{Value: "team-db", Source: SourceLabel, Location: "certificate/payments/db"},
				{Value: "team-ns", Source: SourceNamespaceLabel, Location: "namespace/payments"},
				{Value: "team-pay", Source: SourceMappingFile, Location: "namespace/payments"},
				{Value: "team-web", Source: SourceMappingFile, Location: "domain/example.com"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want := test.expected
			if want == nil {
				want = []Owner{}
			}
			got := test.config.Resolve(test.signals)
			if diff := cmp.Diff(want, got); diff != "" {
				t.Fatalf("Resolve (-want +got):\n%s", diff)
			}
			if len(got) == 0 {
				return
			}
			for _, entry := range got {
				if entry.Value == "" || entry.Source == "" || entry.Location == "" {
					t.Fatalf("incomplete owner record %+v", entry)
				}
			}
		})
	}
}

func TestParseConfigRejectsNormalizedKeyCollisions(t *testing.T) {
	for name, document := range map[string]string{
		"domains":    "domains:\n  Example.com: team-a\n  example.com: team-b\n",
		"namespaces": "namespaces:\n  Payments: team-a\n  payments: team-b\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(document)); err == nil || !strings.Contains(err.Error(), "duplicate normalized key") {
				t.Fatalf("ParseConfig() error = %v", err)
			}
		})
	}
}

func FuzzParseConfig(f *testing.F) {
	for _, seed := range []string{
		"",
		"labelKeys: [scadenza.io/owner]\n",
		"domains: {example.com: team}\n",
		"domains: [\n",
		"namespaces:\n  payments: team-pay\n",
		"labelKeys: 1\n",
		"domains:\n  example.com: {\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, document string) {
		config, err := ParseConfig([]byte(document))
		if err != nil {
			return
		}
		if len(config.LabelKeys()) == 0 {
			t.Fatalf("empty label keys for %q", document)
		}
		for _, key := range config.LabelKeys() {
			if key == ManagedByKey {
				t.Fatalf("managed-by accepted as an owner key for %q", document)
			}
			if strings.TrimSpace(key) != key || key == "" {
				t.Fatalf("unnormalized label key %q for %q", key, document)
			}
		}
		// Resolve must never panic and must never invent an owner.
		for _, names := range [][]string{nil, {"example.com"}, {"a.b.example.com"}} {
			for _, entry := range config.Resolve(Signals{Object: "secret/ns/name", Names: names}) {
				if entry.Value == "" || entry.Source == "" {
					t.Fatalf("invalid owner %+v for %q", entry, document)
				}
			}
		}
	})
}

func TestResolveIsDeterministic(t *testing.T) {
	config := mustConfig(t, "domains:\n  a.example.com: team-a\n  b.example.com: team-b\n")
	signals := Signals{Object: "secret/ns/name", Names: []string{"b.example.com", "a.example.com"}}
	first := fmt.Sprintf("%v", config.Resolve(signals))
	for index := 0; index < 20; index++ {
		if again := fmt.Sprintf("%v", config.Resolve(signals)); again != first {
			t.Fatalf("non-deterministic resolve: %s != %s", again, first)
		}
	}
}
