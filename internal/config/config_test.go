package config

import (
	"errors"
	"strings"
	"testing"
)

const validDocument = `version: 1
domains: [example.com]
hosts: [www.example.com]
hostsFile: hosts.txt
fromCT: false
port: 8443
kube:
  enabled: true
  context: kind-scadenza
  namespaces: [payments]
  ownershipFile: owners.yaml
policy:
  failOn: [live_only, not-compliant-at-issuance]
  strict: true
  minCoverage: 80
`

func TestParseValidDocument(t *testing.T) {
	config, err := Parse([]byte(validDocument))
	if err != nil {
		t.Fatal(err)
	}
	if config.Version != 1 || len(config.Domains) != 1 || config.HostsFile != "hosts.txt" {
		t.Fatalf("config = %+v", config)
	}
	if config.FromCT == nil || *config.FromCT || config.Port == nil || *config.Port != 8443 {
		t.Fatalf("pointers = %+v", config)
	}
	if !config.Kube.Enabled || config.Kube.Context != "kind-scadenza" || len(config.Kube.Namespaces) != 1 {
		t.Fatalf("kube = %+v", config.Kube)
	}
	if !config.Policy.Strict || config.Policy.MinCoverage == nil || *config.Policy.MinCoverage != 80 {
		t.Fatalf("policy = %+v", config.Policy)
	}
}

func TestParseRejectsUnknownKeys(t *testing.T) {
	_, err := Parse([]byte("version: 1\nverbose: true\n"))
	if err == nil || !strings.Contains(err.Error(), "field verbose") {
		t.Fatalf("error = %v, want an unknown-field error", err)
	}
}

func TestParseRejectsBadValues(t *testing.T) {
	cases := map[string]string{
		"missing version": "domains: [example.com]\n",
		"wrong version":   "version: 2\n",
		"bad port":        "version: 1\nport: 70000\n",
		"bad minCoverage": "version: 1\npolicy:\n  minCoverage: 101\n",
		"unknown failOn":  "version: 1\npolicy:\n  failOn: [ct_only, bogus]\n",
		"none combined":   "version: 1\npolicy:\n  failOn: [none, live_only]\n",
		"empty failOn":    "version: 1\npolicy:\n  failOn: []\n",
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(data)); err == nil {
				t.Fatalf("expected an error for %q", data)
			}
		})
	}
}

func TestParseFailOn(t *testing.T) {
	kinds, err := ParseFailOn(" live_only , not-compliant-at-issuance , live_only ")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(kinds, ",") != "live_only,not-compliant-at-issuance" {
		t.Fatalf("kinds = %v", kinds)
	}
	if _, err := ParseFailOn("bogus"); !errors.Is(err, ErrUnknownFailOnKind) {
		t.Fatalf("err = %v", err)
	}
	if _, err := ParseFailOn("none,live_only"); !errors.Is(err, ErrFailOnNoneCombined) {
		t.Fatalf("err = %v", err)
	}
	none, err := ParseFailOn("none")
	if err != nil || len(none) != 1 || none[0] != FailOnNone {
		t.Fatalf("none = %v err = %v", none, err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte("version: 1\n"))
	f.Add([]byte("version: 1\npolicy:\n  failOn: [none]\n"))
	f.Add([]byte("version: 1\ndomains: [example.com]\nport: 443\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		config, err := Parse(data)
		if err == nil && config.Version != 1 {
			t.Fatalf("accepted version %d", config.Version)
		}
	})
}
