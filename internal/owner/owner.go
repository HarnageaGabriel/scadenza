// Package owner resolves certificate ownership from Kubernetes object labels,
// annotations, namespaces, and an optional mapping file. It is pure: it performs
// no I/O, reads no clock, and never infers an owner that was not explicitly
// declared. See docs/ownership.md for the human-facing rules.
package owner

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Source records where an owner value was found, so attribution is auditable.
type Source string

const (
	// SourceLabel means the owner came from an object label.
	SourceLabel Source = "label"
	// SourceAnnotation means the owner came from an object annotation.
	SourceAnnotation Source = "annotation"
	// SourceNamespaceLabel means the owner came from a namespace label.
	SourceNamespaceLabel Source = "namespace-label"
	// SourceNamespaceAnnotation means the owner came from a namespace annotation.
	SourceNamespaceAnnotation Source = "namespace-annotation"
	// SourceMappingFile means the owner came from the ownership mapping file.
	SourceMappingFile Source = "mapping-file"
)

// ManagedByKey is deliberately never treated as an owner: it names the tool that
// manages an object, not the team that owns the certificate. It is dropped even
// when an ownership file lists it.
const ManagedByKey = "app.kubernetes.io/managed-by"

// defaultLabelKeys are consulted when the ownership file lists no labelKeys.
var defaultLabelKeys = []string{"scadenza.io/owner"}

// Owner is one auditable owner attribution.
type Owner struct {
	Value    string `json:"owner"`
	Source   Source `json:"owner_source"`
	Location string `json:"location"`
}

// Config is a parsed ownership mapping file.
type Config struct {
	labelKeys  []string
	domains    map[string]string
	namespaces map[string]string
}

// ParseConfig decodes an ownership mapping file. Unknown fields are rejected so
// that a typo cannot silently disable ownership, and keys and values are
// normalized. An empty document yields the documented defaults.
func ParseConfig(data []byte) (Config, error) {
	var document struct {
		LabelKeys  []string          `yaml:"labelKeys"`
		Domains    map[string]string `yaml:"domains"`
		Namespaces map[string]string `yaml:"namespaces"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&document); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("decode ownership file: %w", err)
	}
	domains, err := normalizeMap(document.Domains, true)
	if err != nil {
		return Config{}, fmt.Errorf("normalize domains: %w", err)
	}
	namespaces, err := normalizeMap(document.Namespaces, false)
	if err != nil {
		return Config{}, fmt.Errorf("normalize namespaces: %w", err)
	}
	return Config{labelKeys: normalizeKeys(document.LabelKeys), domains: domains, namespaces: namespaces}, nil
}

// LabelKeys returns the label and annotation keys this config consults.
func (c Config) LabelKeys() []string { return append([]string(nil), c.labelKeys...) }

// Signals are the raw ownership inputs for one Kubernetes object.
type Signals struct {
	// Object names where label and annotation matches were found.
	Object      string
	Labels      map[string]string
	Annotations map[string]string
	// Namespace names the object namespace and its declared owner signals.
	Namespace            string
	NamespaceLabels      map[string]string
	NamespaceAnnotations map[string]string
	// Names are the certificate DNS names used for domain mapping.
	Names []string
}

// Resolve returns every explicitly declared owner for signals, sorted and
// deduplicated. An empty result means no owner was declared: Resolve never
// infers one.
func (c Config) Resolve(signals Signals) []Owner {
	found := map[string]Owner{}
	for _, key := range c.labelKeys {
		if value, ok := signals.Labels[key]; ok {
			add(found, value, SourceLabel, signals.Object)
		}
	}
	for _, key := range c.labelKeys {
		if value, ok := signals.Annotations[key]; ok {
			add(found, value, SourceAnnotation, signals.Object)
		}
	}
	namespaceLocation := "namespace/" + signals.Namespace
	for _, key := range c.labelKeys {
		if value, ok := signals.NamespaceLabels[key]; ok {
			add(found, value, SourceNamespaceLabel, namespaceLocation)
		}
	}
	for _, key := range c.labelKeys {
		if value, ok := signals.NamespaceAnnotations[key]; ok {
			add(found, value, SourceNamespaceAnnotation, namespaceLocation)
		}
	}
	if signals.Namespace != "" {
		if value, ok := c.namespaces[strings.ToLower(strings.TrimSpace(signals.Namespace))]; ok {
			add(found, value, SourceMappingFile, namespaceLocation)
		}
	}
	if domain, value, ok := c.matchDomain(signals.Names); ok {
		add(found, value, SourceMappingFile, "domain/"+domain)
	}
	result := make([]Owner, 0, len(found))
	for _, owner := range found {
		result = append(result, owner)
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Value != result[j].Value {
			return result[i].Value < result[j].Value
		}
		if result[i].Source != result[j].Source {
			return result[i].Source < result[j].Source
		}
		return result[i].Location < result[j].Location
	})
	return result
}

// matchDomain returns the longest domain mapping entry that covers any name.
func (c Config) matchDomain(names []string) (string, string, bool) {
	best, bestValue := "", ""
	for _, name := range names {
		name = NormalizeDomain(name)
		if name == "" {
			continue
		}
		for domain, value := range c.domains {
			if name != domain && !strings.HasSuffix(name, "."+domain) {
				continue
			}
			if len(domain) > len(best) || (len(domain) == len(best) && domain < best) {
				best, bestValue = domain, value
			}
		}
	}
	if best == "" {
		return "", "", false
	}
	return best, bestValue, true
}

func add(found map[string]Owner, value string, source Source, location string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	key := value + "\x00" + string(source) + "\x00" + location
	found[key] = Owner{Value: value, Source: source, Location: location}
}

func normalizeKeys(keys []string) []string {
	set := map[string]bool{}
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" || key == ManagedByKey {
			continue
		}
		set[key] = true
	}
	if len(set) == 0 {
		return append([]string(nil), defaultLabelKeys...)
	}
	result := make([]string, 0, len(set))
	for key := range set {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func normalizeMap(values map[string]string, domains bool) (map[string]string, error) {
	result := make(map[string]string, len(values))
	originals := make(map[string]string, len(values))
	for original, value := range values {
		key := original
		if domains {
			key = NormalizeDomain(key)
		} else {
			key = strings.ToLower(strings.TrimSpace(key))
		}
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		if previous, exists := originals[key]; exists {
			return nil, fmt.Errorf("duplicate normalized key %q from %q and %q", key, previous, original)
		}
		originals[key] = original
		result[key] = value
	}
	return result, nil
}

// NormalizeDomain is the shared domain normalizer: it lowercases, trims
// surrounding whitespace, strips a leading wildcard label, and removes a
// trailing dot, so a configured key and an observed certificate name turn into
// the same key. It is used for ownership and renewal keys and for the names
// they are matched against.
func NormalizeDomain(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "*.")
	return strings.TrimSuffix(value, ".")
}
