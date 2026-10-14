// Package inventory correlates Certificate Transparency issuances and live TLS
// observations into one entry per certificate, keyed by SHA-256 fingerprint, so
// that "one certificate, every place it appears" can be reported alongside
// expected-versus-observed differences.
package inventory

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/tlsprobe"
)

// Diff kinds reported as findings. They are stable identifiers.
const (
	// KindMatched means the certificate is both issued in CT and presented live.
	KindMatched = "matched"
	// KindCTOnly means the certificate is in CT but no probed host presents it.
	KindCTOnly = "ct_only"
	// KindLiveOnly means a probed host presents a certificate absent from CT.
	KindLiveOnly = "live_only"
	// KindNotChecked means the certificate could not be compared.
	KindNotChecked = "not_checked"
	// KindUnknown means the certificate cannot be correlated at all.
	KindUnknown = "unknown"
	// KindExceeds100D means the certificate lifetime exceeds 100 days.
	KindExceeds100D = "exceeds-100d"
)

// Observation sources.
const (
	SourceCertSpotter = "ct-certspotter"
	SourceCrtSH       = "ct-crtsh"
	SourceTLS         = "tls"
)

// Observation records one place a certificate was seen.
type Observation struct {
	Source   string `json:"source"`
	Location string `json:"location"`
	Detail   string `json:"detail"`
}

// Certificate is one correlated certificate.
type Certificate struct {
	Fingerprint  string        `json:"fingerprint_sha256"`
	Serial       string        `json:"serial"`
	Names        []string      `json:"names"`
	Issuer       string        `json:"issuer"`
	NotBefore    time.Time     `json:"not_before"`
	NotAfter     time.Time     `json:"not_after"`
	LifetimeDays int           `json:"lifetime_days"`
	Verdict100D  string        `json:"verdict_100d"`
	Public       *bool         `json:"public"`
	Observations []Observation `json:"observations"`
}

// Finding is one expected-versus-observed difference or status.
type Finding struct {
	Kind        string   `json:"kind"`
	Fingerprint string   `json:"fingerprint"`
	Names       []string `json:"names"`
	Detail      string   `json:"detail"`
}

// Unresolved records a name that was deliberately not probed.
type Unresolved struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
	Detail string `json:"detail"`
}

// ProbeError records a probe that failed, with its classification.
type ProbeError struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Class  string `json:"class"`
	Detail string `json:"detail"`
}

// Input is the raw material for correlation.
type Input struct {
	Domains  []string
	CT       []ct.Certificate
	Live     []tlsprobe.Result
	Errors   []ProbeError
	Unprobed map[string]string
	Now      time.Time
}

type accumulator struct {
	certificate  Certificate
	hasCT        bool
	hasLive      bool
	anyUntrusted bool
	names        map[string]bool
	observations map[string]Observation
}

// Correlate merges CT issuances and live observations and returns the sorted
// certificates and the sorted findings. It never infers: anything undecidable
// is reported as not_checked or unknown.
func Correlate(in Input) ([]Certificate, []Finding) {
	now := in.Now
	accumulated := map[string]*accumulator{}
	order := []string{}

	live := append([]tlsprobe.Result(nil), in.Live...)
	sort.SliceStable(live, func(i, j int) bool { return lessLive(live[i], live[j]) })
	serialIndex := map[string]string{}
	for _, result := range live {
		if result.Fingerprint == "" {
			continue
		}
		if result.Serial != "" {
			key := issuerKey(result.Issuer, result.Serial)
			if _, ok := serialIndex[key]; !ok {
				serialIndex[key] = result.Fingerprint
			}
		}
	}

	for _, result := range live {
		if result.Fingerprint == "" {
			continue
		}
		key := "fp:" + result.Fingerprint
		entry := ensure(accumulated, &order, key, result.Fingerprint)
		entry.hasLive = true
		if !result.Trusted {
			entry.anyUntrusted = true
		}
		for _, name := range result.Names {
			entry.names[name] = true
		}
		entry.certificate.Issuer = result.Issuer
		entry.certificate.NotBefore = result.NotBefore
		entry.certificate.NotAfter = result.NotAfter
		if result.Serial != "" {
			entry.certificate.Serial = result.Serial
		}
		entry.observations["tls|"+location(result.Host, result.Port)] = Observation{
			Source:   SourceTLS,
			Location: location(result.Host, result.Port),
			Detail:   "leaf presented; trusted=" + boolText(result.Trusted),
		}
	}

	certificates := append([]ct.Certificate(nil), in.CT...)
	sort.SliceStable(certificates, func(i, j int) bool { return lessCT(certificates[i], certificates[j]) })
	for _, record := range certificates {
		key := "ct:" + record.DedupKey
		fingerprint := record.Fingerprint
		if fingerprint != "" {
			key = "fp:" + fingerprint
		} else if record.Serial != "" {
			if matched, ok := serialIndex[issuerKey(record.Issuer, record.Serial)]; ok {
				fingerprint = matched
				key = "fp:" + matched
			}
		}
		entry := ensure(accumulated, &order, key, fingerprint)
		entry.hasCT = true
		for _, name := range record.SubjectNames {
			name = normalizeName(name)
			if name != "" {
				entry.names[name] = true
			}
		}
		if entry.certificate.Issuer == "" {
			entry.certificate.Issuer = record.Issuer
		}
		if entry.certificate.Serial == "" {
			entry.certificate.Serial = normalizeSerial(record.Serial)
		}
		if entry.certificate.NotBefore.IsZero() || entry.certificate.NotBefore.After(record.NotBefore) {
			entry.certificate.NotBefore = record.NotBefore
		}
		if entry.certificate.NotAfter.IsZero() || entry.certificate.NotAfter.After(record.NotAfter) {
			entry.certificate.NotAfter = record.NotAfter
		}
		source := SourceCrtSH
		if record.Source == "certspotter" {
			source = SourceCertSpotter
		}
		entry.observations[source+"|"+record.Source] = Observation{
			Source:   source,
			Location: record.Source,
			Detail:   "Certificate Transparency issuance",
		}
	}

	states := in.stateLookup()
	result := make([]Certificate, 0, len(order))
	findings := make([]Finding, 0, len(order))
	for _, key := range order {
		entry := accumulated[key]
		certificate := entry.certificate
		certificate.Names = sortedKeys(entry.names)
		certificate.LifetimeDays, certificate.Verdict100D = lifetime(certificate.NotBefore, certificate.NotAfter)
		if entry.hasLive {
			public := !entry.anyUntrusted
			certificate.Public = &public
		}
		certificate.Observations = sortedObservations(entry.observations)
		kind, detail := classify(entry, states, in.Domains, certificate, now)
		result = append(result, certificate)
		findings = append(findings, Finding{Kind: kind, Fingerprint: certificate.Fingerprint, Names: certificate.Names, Detail: detail})
		if certificate.Verdict100D == "exceeds" && !certificate.NotAfter.Before(now) {
			findings = append(findings, Finding{
				Kind:        KindExceeds100D,
				Fingerprint: certificate.Fingerprint,
				Names:       certificate.Names,
				Detail:      "validity exceeds 100 days; renewal must fit the 100-day limit",
			})
		}
	}
	sort.SliceStable(result, func(i, j int) bool { return lessCertificate(result[i], result[j]) })
	sort.SliceStable(findings, func(i, j int) bool { return lessFinding(findings[i], findings[j]) })
	return result, findings
}

// stateLookup indexes observed names, failed probe hosts, and unprobed names.
type stateLookup struct {
	observed   map[string]bool
	hostErrors map[string]string
	unprobed   map[string]string
}

func (in Input) stateLookup() stateLookup {
	lookup := stateLookup{observed: map[string]bool{}, hostErrors: map[string]string{}, unprobed: map[string]string{}}
	for _, result := range in.Live {
		for _, name := range result.Names {
			lookup.observed[normalizeName(name)] = true
		}
	}
	for _, probeError := range in.Errors {
		key := normalizeName(probeError.Host)
		if _, ok := lookup.hostErrors[key]; !ok {
			lookup.hostErrors[key] = probeError.Class
		}
	}
	for name, reason := range in.Unprobed {
		lookup.unprobed[normalizeName(name)] = reason
	}
	return lookup
}

func (lookup stateLookup) state(name string) string {
	if lookup.observed[name] {
		return "observed"
	}
	if class, ok := lookup.hostErrors[name]; ok {
		return "probe-error:" + class
	}
	if reason, ok := lookup.unprobed[name]; ok {
		return reason
	}
	return "not-probed"
}

func classify(entry *accumulator, lookup stateLookup, domains []string, certificate Certificate, now time.Time) (string, string) {
	switch {
	case entry.hasCT && entry.hasLive:
		return KindMatched, "presented by a probed host and issued in Certificate Transparency"
	case !entry.hasCT && entry.hasLive:
		detail := "presented by a probed host but absent from Certificate Transparency results"
		if certificate.Public != nil && !*certificate.Public {
			detail += "; private_or_untrusted"
		}
		return KindLiveOnly, detail
	}
	if certificate.Fingerprint == "" && certificate.Serial == "" {
		return KindUnknown, "cannot correlate: Certificate Transparency record has no fingerprint or serial number"
	}
	if !certificate.NotAfter.IsZero() && certificate.NotAfter.Before(now) {
		return KindNotChecked, "certificate expired before the scan; not compared"
	}
	relevant := relevantNames(certificate.Names, domains)
	if len(relevant) == 0 {
		return KindNotChecked, "no in-scope name was probed"
	}
	blocked := []string{}
	for _, name := range relevant {
		if state := lookup.state(name); state != "observed" {
			blocked = append(blocked, name+" ("+state+")")
		}
	}
	if len(blocked) > 0 {
		sort.Strings(blocked)
		return KindNotChecked, "not verified as absent: " + strings.Join(blocked, ", ")
	}
	return KindCTOnly, "issued in Certificate Transparency and not presented by any probed host"
}

func relevantNames(names []string, domains []string) []string {
	result := make([]string, 0, len(names))
	for _, name := range names {
		if inScope(name, domains) {
			result = append(result, name)
		}
	}
	return result
}

func inScope(name string, domains []string) bool {
	base := strings.TrimPrefix(normalizeName(name), "*.")
	if base == "" {
		return false
	}
	for _, domain := range domains {
		if base == domain || strings.HasSuffix(base, "."+domain) {
			return true
		}
	}
	return false
}

func ensure(accumulated map[string]*accumulator, order *[]string, key, fingerprint string) *accumulator {
	if entry, ok := accumulated[key]; ok {
		return entry
	}
	entry := &accumulator{
		certificate:  Certificate{Fingerprint: fingerprint},
		names:        map[string]bool{},
		observations: map[string]Observation{},
	}
	accumulated[key] = entry
	*order = append(*order, key)
	return entry
}

func lifetime(notBefore, notAfter time.Time) (int, string) {
	if notBefore.IsZero() || notAfter.IsZero() || notAfter.Before(notBefore) {
		return 0, "unknown"
	}
	duration := notAfter.Sub(notBefore)
	days := int(duration / (24 * time.Hour))
	if duration > 100*24*time.Hour {
		return days, "exceeds"
	}
	return days, "ok"
}

// issuerKey normalizes an issuer name and serial number for crt.sh correlation.
func issuerKey(issuer, serial string) string {
	return normalizeIssuer(issuer) + "|" + normalizeSerial(serial)
}

func normalizeIssuer(value string) string {
	fields := strings.FieldsFunc(strings.ToLower(value), func(r rune) bool { return r == ',' || r == '/' || r == ';' })
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.Join(strings.Fields(field), "")
		if field != "" {
			parts = append(parts, field)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func normalizeSerial(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, ":", "")
	value = strings.TrimPrefix(value, "0x")
	value = strings.TrimLeft(value, "0")
	return value
}

func normalizeName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.TrimSuffix(value, ".")
}

func location(host string, port int) string { return host + ":" + strconv.Itoa(port) }

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func sortedKeys(set map[string]bool) []string {
	result := make([]string, 0, len(set))
	for key := range set {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func sortedObservations(set map[string]Observation) []Observation {
	result := make([]Observation, 0, len(set))
	for _, observation := range set {
		result = append(result, observation)
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Source != result[j].Source {
			return result[i].Source < result[j].Source
		}
		if result[i].Location != result[j].Location {
			return result[i].Location < result[j].Location
		}
		return result[i].Detail < result[j].Detail
	})
	return result
}

func lessLive(a, b tlsprobe.Result) bool {
	if a.Fingerprint != b.Fingerprint {
		return a.Fingerprint < b.Fingerprint
	}
	if a.Host != b.Host {
		return a.Host < b.Host
	}
	return a.Port < b.Port
}

func lessCT(a, b ct.Certificate) bool {
	if !a.NotBefore.Equal(b.NotBefore) {
		return a.NotBefore.Before(b.NotBefore)
	}
	if a.Fingerprint != b.Fingerprint {
		return a.Fingerprint < b.Fingerprint
	}
	if a.DedupKey != b.DedupKey {
		return a.DedupKey < b.DedupKey
	}
	if a.Serial != b.Serial {
		return a.Serial < b.Serial
	}
	return strings.Join(a.SubjectNames, ",") < strings.Join(b.SubjectNames, ",")
}

func lessCertificate(a, b Certificate) bool {
	if !a.NotBefore.Equal(b.NotBefore) {
		return a.NotBefore.After(b.NotBefore)
	}
	if a.Fingerprint != b.Fingerprint {
		return a.Fingerprint < b.Fingerprint
	}
	if a.Serial != b.Serial {
		return a.Serial < b.Serial
	}
	if a.Issuer != b.Issuer {
		return a.Issuer < b.Issuer
	}
	return strings.Join(a.Names, ",") < strings.Join(b.Names, ",")
}

func lessFinding(a, b Finding) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.Fingerprint != b.Fingerprint {
		return a.Fingerprint < b.Fingerprint
	}
	if namesA, namesB := strings.Join(a.Names, ","), strings.Join(b.Names, ","); namesA != namesB {
		return namesA < namesB
	}
	return a.Detail < b.Detail
}
