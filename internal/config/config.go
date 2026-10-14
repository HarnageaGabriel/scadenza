// Package config loads the optional scadenza.yaml configuration file. Loading
// is explicit-only: nothing is auto-loaded, so the same invocation always reads
// the same inputs. Unknown keys are rejected so a typo cannot silently disable
// a setting.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/owner"
	"gopkg.in/yaml.v3"
)

// FailOnNone disables exit 3 when it is the only fail-on kind.
const FailOnNone = "none"

// FailOnKinds lists the accepted --fail-on kinds in canonical order. The
// renewal kinds come from M4b: renew-before-exceeds-lifetime and
// renewal-degraded fail by default, the rest are reported only.
var FailOnKinds = []string{
	"ct_only",
	"live_only",
	"exceeds-100d",
	"not-compliant-at-issuance",
	"renew-before-exceeds-lifetime",
	"renewal-degraded",
	"renew-before-loop-at-next-limit",
	"duration-exceeds-next-limit",
	"manual-renewal-after-limit",
	"renewal-config-invalid",
	FailOnNone,
}

// ErrUnknownFailOnKind marks an unrecognized --fail-on kind.
var ErrUnknownFailOnKind = errors.New("unknown fail-on kind")

// ErrFailOnNoneCombined marks `none` combined with another kind.
var ErrFailOnNoneCombined = errors.New("fail-on none cannot be combined with other kinds")

// ErrEmptyFailOnList marks an empty or whitespace-only fail-on list.
var ErrEmptyFailOnList = errors.New("fail-on list must not be empty")

// ErrInvalid marks a configuration file that does not match the schema.
var ErrInvalid = errors.New("invalid configuration")

// DefaultFailOn is the documented default failure policy. ct_only is reported
// but excluded (CDNs issue several certificates in parallel, so it is noisy),
// and exceeds-100d stays a readiness signal rather than a compliance failure.
// M4b turns on renew-before-exceeds-lifetime and renewal-degraded: both mean
// renewal is broken or about to loop now, not merely a configuration that may
// break later.
func DefaultFailOn() []string {
	return []string{
		"live_only",
		"not-compliant-at-issuance",
		"renew-before-exceeds-lifetime",
		"renewal-degraded",
	}
}

// RenewalManual is the only accepted renewal declaration value: the operator
// renews the certificate by hand.
const RenewalManual = "manual"

// Config is a parsed configuration file.
type Config struct {
	Version   int
	Domains   []string
	Hosts     []string
	HostsFile string
	FromCT    *bool
	Port      *int
	Kube      Kube
	Policy    Policy
	// Renewal maps a domain to a declared renewal mode (only "manual"). It is
	// evidence for renewal classification: an automatic mechanism still wins.
	Renewal map[string]string
}

// Kube configures the Kubernetes source.
type Kube struct {
	Enabled       bool
	Context       string
	Namespaces    []string
	OwnershipFile string
}

// Policy configures the failure policy.
type Policy struct {
	FailOn      []string
	Strict      bool
	MinCoverage *int
}

type document struct {
	Version   int               `yaml:"version"`
	Domains   []string          `yaml:"domains"`
	Hosts     []string          `yaml:"hosts"`
	HostsFile string            `yaml:"hostsFile"`
	FromCT    *bool             `yaml:"fromCT"`
	Port      *int              `yaml:"port"`
	Kube      *kubeDoc          `yaml:"kube"`
	Policy    *policyDoc        `yaml:"policy"`
	Renewal   map[string]string `yaml:"renewal"`
}

type kubeDoc struct {
	Enabled       bool     `yaml:"enabled"`
	Context       string   `yaml:"context"`
	Namespaces    []string `yaml:"namespaces"`
	OwnershipFile string   `yaml:"ownershipFile"`
}

type policyDoc struct {
	FailOn      []string `yaml:"failOn"`
	Strict      bool     `yaml:"strict"`
	MinCoverage *int     `yaml:"minCoverage"`
}

// Load reads and parses an explicit configuration file.
func Load(path string) (Config, error) {
	//nolint:gosec // G304: the path comes from --config, supplied by the user.
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config file: %w", err)
	}
	config, err := Parse(data)
	if err != nil {
		return Config{}, err
	}
	base := filepath.Dir(path)
	if config.HostsFile != "" && !filepath.IsAbs(config.HostsFile) {
		config.HostsFile = filepath.Join(base, config.HostsFile)
	}
	if config.Kube.OwnershipFile != "" && !filepath.IsAbs(config.Kube.OwnershipFile) {
		config.Kube.OwnershipFile = filepath.Join(base, config.Kube.OwnershipFile)
	}
	return config, nil
}

// Parse decodes a configuration document with strict key checking.
func Parse(data []byte) (Config, error) {
	var decoded document
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&decoded); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("decode config file: %w", err)
	}
	if decoded.Version != 1 {
		return Config{}, fmt.Errorf("%w: version must be 1, got %d", ErrInvalid, decoded.Version)
	}
	config := Config{
		Version:   decoded.Version,
		Domains:   decoded.Domains,
		Hosts:     decoded.Hosts,
		HostsFile: decoded.HostsFile,
		FromCT:    decoded.FromCT,
		Port:      decoded.Port,
	}
	if decoded.Port != nil && (*decoded.Port < 1 || *decoded.Port > 65535) {
		return Config{}, fmt.Errorf("%w: port must be between 1 and 65535", ErrInvalid)
	}
	if decoded.Kube != nil {
		config.Kube = Kube{
			Enabled:       decoded.Kube.Enabled,
			Context:       decoded.Kube.Context,
			Namespaces:    decoded.Kube.Namespaces,
			OwnershipFile: decoded.Kube.OwnershipFile,
		}
	}
	if decoded.Policy != nil {
		config.Policy.Strict = decoded.Policy.Strict
		config.Policy.MinCoverage = decoded.Policy.MinCoverage
		if decoded.Policy.MinCoverage != nil && (*decoded.Policy.MinCoverage < 0 || *decoded.Policy.MinCoverage > 100) {
			return Config{}, fmt.Errorf("%w: minCoverage must be between 0 and 100", ErrInvalid)
		}
		if decoded.Policy.FailOn != nil {
			kinds, err := ParseFailOnList(decoded.Policy.FailOn)
			if err != nil {
				return Config{}, err
			}
			config.Policy.FailOn = kinds
		}
	}
	renewal, renewalErr := normalizeRenewal(decoded.Renewal)
	if renewalErr != nil {
		return Config{}, renewalErr
	}
	config.Renewal = renewal
	return config, nil
}

// normalizeRenewal validates the per-domain renewal declarations. Keys are
// normalized with the shared domain normalizer, so "*.Example.COM." and
// "example.com" are the same key, and a malformed key is rejected instead of
// silently failing to match a certificate name. Only the documented manual mode
// is accepted, so a typo cannot silently change a classification.
func normalizeRenewal(values map[string]string) (map[string]string, error) {
	result := make(map[string]string, len(values))
	for domain, mode := range values {
		normalized := owner.NormalizeDomain(domain)
		if _, err := ct.NormalizeDomain(normalized); err != nil {
			return nil, fmt.Errorf("%w: renewal key %q is not a valid domain", ErrInvalid, domain)
		}
		value := strings.ToLower(strings.TrimSpace(mode))
		if value != RenewalManual {
			return nil, fmt.Errorf("%w: renewal for %q must be %q", ErrInvalid, domain, RenewalManual)
		}
		result[normalized] = value
	}
	return result, nil
}

// ParseFailOn parses a comma-separated --fail-on value.
func ParseFailOn(value string) ([]string, error) {
	return ParseFailOnList(strings.Split(value, ","))
}

// ParseFailOnList validates and normalizes a list of fail-on kinds. An empty
// or whitespace-only list is invalid; only the explicit kind `none` disables
// exit 3.
func ParseFailOnList(values []string) ([]string, error) {
	present := map[string]bool{}
	for _, raw := range values {
		kind := strings.TrimSpace(raw)
		if kind == "" {
			continue
		}
		if !validFailOnKind(kind) {
			return nil, fmt.Errorf("%w: %q", ErrUnknownFailOnKind, kind)
		}
		present[kind] = true
	}
	if len(present) == 0 {
		return nil, ErrEmptyFailOnList
	}
	if present[FailOnNone] && len(present) > 1 {
		return nil, ErrFailOnNoneCombined
	}
	result := make([]string, 0, len(present))
	for _, kind := range FailOnKinds {
		if present[kind] {
			result = append(result, kind)
		}
	}
	return result, nil
}

func validFailOnKind(kind string) bool {
	for _, candidate := range FailOnKinds {
		if candidate == kind {
			return true
		}
	}
	return false
}
