// Package inventory correlates Certificate Transparency issuances and live TLS
// observations into one entry per certificate, keyed by SHA-256 fingerprint, so
// that "one certificate, every place it appears" can be reported alongside
// expected-versus-observed differences.
package inventory

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/azurekv"
	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/kube"
	"github.com/HarnageaGabriel/scadenza/internal/owner"
	"github.com/HarnageaGabriel/scadenza/internal/policy"
	"github.com/HarnageaGabriel/scadenza/internal/renewal"
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
	// KindKubeOnly means the certificate was read only from Kubernetes.
	KindKubeOnly = "kube_only"
	// KindNotCompliantAtIssuance means the lifetime exceeded the maximum
	// validity in force when the certificate was issued.
	KindNotCompliantAtIssuance = "not-compliant-at-issuance"
)

// Correlation methods state how a certificate's identity was established.
const (
	// CorrelationSHA256 means the entry is keyed by SHA-256 fingerprint.
	CorrelationSHA256 = "sha256"
	// CorrelationIssuerSerial means the entry was matched by issuer and serial.
	CorrelationIssuerSerial = "issuer_serial"
	// CorrelationNamesExpiry means a Kubernetes status observation was weakly
	// joined to exactly one CT or live certificate by equal names and notAfter.
	CorrelationNamesExpiry = "names_and_expiry"
	// CorrelationUnresolved means nothing could correlate the record.
	CorrelationUnresolved = "unresolved"
)

// Observation sources.
const (
	SourceCertSpotter = "ct-certspotter"
	SourceCrtSH       = "ct-crtsh"
	SourceTLS         = "tls"
	// SourceKubeSecret marks a certificate read from a kubernetes.io/tls Secret.
	SourceKubeSecret = kube.SourceSecret
	// SourceCertManager marks facts read from a cert-manager Certificate.
	SourceCertManager = kube.SourceCertManager
	// SourceAzureKeyVault marks facts read from an Azure Key Vault certificate.
	SourceAzureKeyVault = azurekv.SourceName
)

// VerdictNotApplicable is reported when the 100-day rule does not apply, for
// example to a Kubernetes certificate that cannot be classified as public.
const VerdictNotApplicable = "not_applicable"

// Observation records one place a certificate was seen.
type Observation struct {
	Source   string `json:"source"`
	Location string `json:"location"`
	Detail   string `json:"detail"`
	// Kubernetes carries the raw Kubernetes and cert-manager facts, when the
	// observation was read from a cluster.
	Kubernetes *kube.Kubernetes `json:"kubernetes,omitempty"`
	// KeyVault carries the additive read-only certificate policy and identity
	// facts when the observation came from Azure Key Vault.
	KeyVault *azurekv.Facts `json:"azure_keyvault,omitempty"`
}

// Certificate is one correlated certificate.
type Certificate struct {
	Fingerprint  string    `json:"fingerprint_sha256"`
	Serial       string    `json:"serial"`
	Names        []string  `json:"names"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	LifetimeDays int       `json:"lifetime_days"`
	Verdict100D  string    `json:"verdict_100d"`
	// CorrelationMethod is sha256, issuer_serial, names_and_expiry, or
	// unresolved: the weakest piece of evidence that placed this certificate in
	// the inventory.
	CorrelationMethod string `json:"correlation_method"`
	// Policy is the dated validity assessment; verdict_100d stays unchanged.
	Policy       policy.Assessment `json:"policy"`
	Public       *bool             `json:"public"`
	Observations []Observation     `json:"observations"`
	// Owners lists every explicitly declared owner, each with the rule that
	// produced it. It is empty when no ownership rule matched.
	Owners []owner.Owner `json:"owners"`
	// Renewal is the M4b renewal classification: mode, health, evidence, and
	// the configuration risks that will break under shorter lifetimes. It is
	// always present; missing evidence is reported as unknown.
	Renewal renewal.Classification `json:"renewal"`
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
	Domains []string
	CT      []ct.Certificate
	Kube    []kube.Certificate
	Azure   []azurekv.Certificate
	Live    []tlsprobe.Result
	Errors  []ProbeError
	// RenewalModes maps a domain to an explicitly declared renewal mode from
	// scadenza.yaml (only "manual"). It is evidence, never an override of an
	// automatic mechanism.
	RenewalModes map[string]string
	Unprobed     map[string]string
	Now          time.Time
}

type accumulator struct {
	certificate  Certificate
	hasCT        bool
	hasLive      bool
	hasKube      bool
	hasAzure     bool
	selfSigned   bool
	kubePublic   bool
	trustChecked bool
	anyTrusted   bool
	anyUntrusted bool
	names        map[string]bool
	owners       map[string]owner.Owner
	observations map[string]Observation
	method       string
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
		entry.setMethod(CorrelationSHA256)
		entry.hasLive = true
		entry.trustChecked = true
		if result.Trusted {
			entry.anyTrusted = true
		} else {
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
		switch {
		case record.Fingerprint != "":
			entry.setMethod(CorrelationSHA256)
		case fingerprint != "":
			entry.setMethod(CorrelationIssuerSerial)
		default:
			entry.setMethod(CorrelationUnresolved)
		}
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

	azureRecords := append([]azurekv.Certificate(nil), in.Azure...)
	sort.SliceStable(azureRecords, func(i, j int) bool {
		if azureRecords[i].Facts.Vault != azureRecords[j].Facts.Vault {
			return azureRecords[i].Facts.Vault < azureRecords[j].Facts.Vault
		}
		if azureRecords[i].Facts.Name != azureRecords[j].Facts.Name {
			return azureRecords[i].Facts.Name < azureRecords[j].Facts.Name
		}
		return azureRecords[i].Facts.Version < azureRecords[j].Facts.Version
	})
	for _, record := range azureRecords {
		key := "azurekv:" + record.Facts.Vault + "/" + record.Facts.Name + "/" + record.Facts.Version
		if record.Fingerprint != "" {
			key = "fp:" + record.Fingerprint
		}
		entry := ensure(accumulated, &order, key, record.Fingerprint)
		if record.Fingerprint != "" {
			entry.setMethod(CorrelationSHA256)
		} else {
			entry.setMethod(CorrelationUnresolved)
		}
		entry.hasAzure = true
		if strings.EqualFold(strings.TrimSpace(record.Facts.Issuer), "self") {
			entry.selfSigned = true
		}
		for _, name := range record.Names {
			if normalized := normalizeName(name); normalized != "" {
				entry.names[normalized] = true
			}
		}
		if entry.certificate.Issuer == "" {
			entry.certificate.Issuer = record.Facts.Issuer
		}
		if entry.certificate.Serial == "" {
			entry.certificate.Serial = normalizeSerial(record.Serial)
		}
		if !record.NotBefore.IsZero() && (entry.certificate.NotBefore.IsZero() || entry.certificate.NotBefore.After(record.NotBefore)) {
			entry.certificate.NotBefore = record.NotBefore
		}
		if !record.NotAfter.IsZero() && (entry.certificate.NotAfter.IsZero() || entry.certificate.NotAfter.After(record.NotAfter)) {
			entry.certificate.NotAfter = record.NotAfter
		}
		for _, declared := range record.Owners {
			entry.owners[ownerKey(declared)] = declared
		}
		facts := record.Facts
		entry.observations[SourceAzureKeyVault+"|"+facts.Vault+"/"+facts.Name+"@"+facts.Version] = Observation{
			Source:   SourceAzureKeyVault,
			Location: facts.Vault + "/" + facts.Name + "@" + facts.Version,
			Detail:   "read-only certificate, policy, and public CER",
			KeyVault: &facts,
		}
	}

	kubeRecords := append([]kube.Certificate(nil), in.Kube...)
	sort.SliceStable(kubeRecords, func(i, j int) bool { return lessKube(kubeRecords[i], kubeRecords[j]) })
	for _, record := range kubeRecords {
		if record.Fingerprint != "" {
			continue
		}
		// Only a record that carries certificate facts can be weakly joined by
		// name set and expiry. Records without them, such as a TLS Secret seen
		// through metadata only, are still reported with their owner signals.
		if !record.NotAfter.IsZero() && len(record.Names) > 0 {
			matches := []string{}
			for key, entry := range accumulated {
				if (!entry.hasCT && !entry.hasLive) ||
					entry.certificate.NotAfter.IsZero() ||
					!entry.certificate.NotAfter.Equal(record.NotAfter) ||
					!sameNameSet(entry.names, kubeNameSet(record.Names)) {
					continue
				}
				matches = append(matches, key)
			}
			if len(matches) == 1 {
				entry := accumulated[matches[0]]
				entry.method = CorrelationNamesExpiry
				addKubeRecord(entry, record)
				continue
			}
		}
		entry := ensure(accumulated, &order, "kube:"+record.DedupKey, "")
		entry.setMethod(CorrelationUnresolved)
		addKubeRecord(entry, record)
	}
	for _, record := range kubeRecords {
		if record.Fingerprint == "" {
			continue
		}
		key := "fp:" + record.Fingerprint
		entry := ensure(accumulated, &order, key, record.Fingerprint)
		entry.setMethod(CorrelationSHA256)
		addKubeRecord(entry, record)
	}

	return finishCorrelation(accumulated, order, in, now)
}

func addKubeRecord(entry *accumulator, record kube.Certificate) {
	entry.hasKube = true
	for _, name := range record.Names {
		if normalized := normalizeName(name); normalized != "" {
			entry.names[normalized] = true
		}
	}
	if entry.certificate.Issuer == "" {
		entry.certificate.Issuer = record.Issuer
	}
	if entry.certificate.Serial == "" {
		entry.certificate.Serial = normalizeSerial(record.Serial)
	}
	if !record.NotBefore.IsZero() && (entry.certificate.NotBefore.IsZero() || entry.certificate.NotBefore.After(record.NotBefore)) {
		entry.certificate.NotBefore = record.NotBefore
	}
	if !record.NotAfter.IsZero() && (entry.certificate.NotAfter.IsZero() || entry.certificate.NotAfter.After(record.NotAfter)) {
		entry.certificate.NotAfter = record.NotAfter
	}
	if record.Public != nil {
		entry.trustChecked = true
		if *record.Public {
			entry.kubePublic = true
			entry.anyTrusted = true
		}
	}
	for _, declared := range record.Owners {
		entry.owners[ownerKey(declared)] = declared
	}
	for _, observation := range record.Observations {
		entry.observations[observation.Source+"|"+observation.Location] = Observation{
			Source:     observation.Source,
			Location:   observation.Location,
			Detail:     observation.Detail,
			Kubernetes: observation.Kubernetes,
		}
	}
}

func finishCorrelation(accumulated map[string]*accumulator, order []string, in Input, now time.Time) ([]Certificate, []Finding) {
	states := in.stateLookup()
	result := make([]Certificate, 0, len(order))
	findings := make([]Finding, 0, len(order))
	for _, key := range order {
		entry := accumulated[key]
		certificate := entry.certificate
		certificate.Names = sortedKeys(entry.names)
		certificate.LifetimeDays, certificate.Verdict100D = lifetime(certificate.NotBefore, certificate.NotAfter)
		certificate.CorrelationMethod = entry.method
		if certificate.CorrelationMethod == "" {
			certificate.CorrelationMethod = CorrelationUnresolved
		}
		certificate.Policy = policy.Assess(certificate.NotBefore, certificate.NotAfter)
		switch {
		case entry.anyTrusted || entry.kubePublic:
			public := true
			certificate.Public = &public
		case entry.trustChecked:
			public := false
			certificate.Public = &public
		}
		if entry.selfSigned {
			private := false
			certificate.Public = &private
			certificate.Verdict100D = VerdictNotApplicable
		} else if entry.hasKube && !entry.hasCT && !entry.hasLive && certificate.Public == nil {
			// A certificate that only Kubernetes holds, and that does not verify
			// against the system roots, cannot be classified as public or
			// private, so the 100-day rule does not apply to it.
			certificate.Verdict100D = VerdictNotApplicable
		}
		certificate.Owners = sortedOwners(entry.owners)
		certificate.Observations = sortedObservations(entry.observations)
		certificate.Renewal = renewal.Classify(renewalInput(certificate, in))
		kind, detail := classify(entry, states, in.Domains, certificate, now)
		result = append(result, certificate)
		findings = append(findings, Finding{Kind: kind, Fingerprint: certificate.Fingerprint, Names: certificate.Names, Detail: detail})
		for _, risk := range certificate.Renewal.Risks {
			findings = append(findings, Finding{
				Kind:        risk.Kind,
				Fingerprint: certificate.Fingerprint,
				Names:       certificate.Names,
				Detail:      risk.Detail,
			})
		}
		if certificate.Verdict100D == "exceeds" && !certificate.NotAfter.Before(now) {
			findings = append(findings, Finding{
				Kind:        KindExceeds100D,
				Fingerprint: certificate.Fingerprint,
				Names:       certificate.Names,
				Detail:      "validity exceeds 100 days; renewal must fit the 100-day limit",
			})
		}
		if validLifetime(certificate.NotBefore, certificate.NotAfter) && !certificate.NotAfter.Before(now) &&
			!certificate.Policy.CompliantAtIssuance {
			findings = append(findings, Finding{
				Kind:        KindNotCompliantAtIssuance,
				Fingerprint: certificate.Fingerprint,
				Names:       certificate.Names,
				Detail:      nonComplianceDetail(certificate),
			})
		}
	}
	sort.SliceStable(result, func(i, j int) bool { return lessCertificate(result[i], result[j]) })
	sort.SliceStable(findings, func(i, j int) bool { return lessFinding(findings[i], findings[j]) })
	return result, findings
}

// stateLookup indexes the host names that were actually probed (successfully
// or not) plus the names deliberately left unprobed.
type stateLookup struct {
	observed   map[string]bool
	hostErrors map[string]string
	unprobed   map[string]string
}

func (in Input) stateLookup() stateLookup {
	lookup := stateLookup{observed: map[string]bool{}, hostErrors: map[string]string{}, unprobed: map[string]string{}}
	// Only the host that answered counts as observed. A name that merely
	// appears as a SAN on another host's certificate was never probed, so it
	// must not be treated as served by this scan.
	for _, result := range in.Live {
		if normalized := normalizeName(result.Host); normalized != "" {
			lookup.observed[normalized] = true
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
	case !entry.hasCT && !entry.hasLive && entry.hasKube:
		return KindKubeOnly, "read from Kubernetes and not observed in Certificate Transparency or a live handshake"
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

// setMethod keeps the weakest correlation evidence, so the reported strength is
// never stronger than the least certain observation in the entry.
func (a *accumulator) setMethod(method string) {
	if a.method == "" || correlationRank(method) < correlationRank(a.method) {
		a.method = method
	}
}

func correlationRank(method string) int {
	switch method {
	case CorrelationSHA256:
		return 3
	case CorrelationIssuerSerial:
		return 2
	case CorrelationNamesExpiry:
		return 1
	default:
		return 0
	}
}

func kubeNameSet(names []string) map[string]bool {
	result := map[string]bool{}
	for _, name := range names {
		if normalized := normalizeName(name); normalized != "" {
			result[normalized] = true
		}
	}
	return result
}

func sameNameSet(left, right map[string]bool) bool {
	if len(left) == 0 || len(left) != len(right) {
		return false
	}
	for name := range left {
		normalized := normalizeName(name)
		if normalized == "" || !right[normalized] {
			return false
		}
	}
	return true
}

func validLifetime(notBefore, notAfter time.Time) bool {
	return !notBefore.IsZero() && !notAfter.IsZero() && !notAfter.Before(notBefore)
}

func nonComplianceDetail(certificate Certificate) string {
	return fmt.Sprintf(
		"lifetime %d days exceeds the %d-day maximum validity in force at issuance",
		certificate.LifetimeDays, certificate.Policy.MaxValidityAtIssuanceDays,
	)
}

func ensure(accumulated map[string]*accumulator, order *[]string, key, fingerprint string) *accumulator {
	if entry, ok := accumulated[key]; ok {
		return entry
	}
	entry := &accumulator{
		certificate:  Certificate{Fingerprint: fingerprint},
		names:        map[string]bool{},
		owners:       map[string]owner.Owner{},
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

// renewalInput assembles the pure renewal classification input from the facts
// already correlated for one certificate. It adds no new reads: every field
// comes from an observation or from the CT records already fetched.
func renewalInput(certificate Certificate, in Input) renewal.Input {
	input := renewal.Input{
		Names:        certificate.Names,
		NotBefore:    certificate.NotBefore,
		NotAfter:     certificate.NotAfter,
		Policy:       certificate.Policy,
		DeclaredMode: renewal.Mode(declaredRenewalMode(certificate.Names, in.RenewalModes)),
		Now:          in.Now,
	}
	for _, observation := range certificate.Observations {
		switch observation.Source {
		case SourceCertSpotter, SourceCrtSH:
			input.HasCT = true
		case SourceTLS:
			input.HasLive = true
		case SourceKubeSecret:
			input.HasKube = true
			if observation.Kubernetes != nil {
				input.Secrets = append(input.Secrets, renewal.Secret{CertificateName: observation.Kubernetes.CertificateName})
			}
		case SourceAzureKeyVault:
			if observation.KeyVault != nil && input.KeyVault == nil {
				input.KeyVault = &renewal.KeyVault{
					Issuer:         observation.KeyVault.Issuer,
					ValidityMonths: observation.KeyVault.PolicyValidityMonths,
				}
				for _, action := range observation.KeyVault.LifetimeActions {
					input.KeyVault.LifetimeActions = append(input.KeyVault.LifetimeActions, renewal.LifetimeAction{
						Type:               action.Type,
						DaysBeforeExpiry:   action.DaysBeforeExpiry,
						LifetimePercentage: action.LifetimePercentage,
					})
				}
			}
		case SourceCertManager:
			input.HasKube = true
			if observation.Kubernetes != nil && input.Manager == nil {
				resource := observation.Kubernetes
				input.Manager = &renewal.Manager{
					IssuerType:            resource.IssuerType,
					ACMEServer:            resource.ACMEServer,
					Duration:              resource.Duration,
					RenewBefore:           resource.RenewBefore,
					RenewBeforePercentage: resource.RenewBeforePercentage,
					StatusNotAfter:        resource.NotAfter,
					RenewalTime:           resource.RenewalTime,
					Ready:                 resource.Ready,
					ReadyReason:           resource.ReadyReason,
				}
			}
		}
	}
	for _, record := range in.CT {
		input.CT = append(input.CT, renewal.Issuance{
			Names:       record.SubjectNames,
			NotBefore:   record.NotBefore,
			Issuer:      record.Issuer,
			Fingerprint: record.Fingerprint,
			Serial:      record.Serial,
		})
	}
	return input
}

// declaredRenewalMode returns the explicitly declared renewal mode for any of
// the certificate's names, using the same domain (and subdomain) matching as
// ownership. An empty result means nothing was declared.
func declaredRenewalMode(names []string, modes map[string]string) string {
	if len(modes) == 0 {
		return ""
	}
	best, value := "", ""
	for _, name := range names {
		normalized := owner.NormalizeDomain(name)
		if normalized == "" {
			continue
		}
		for domain, mode := range modes {
			if normalized != domain && !strings.HasSuffix(normalized, "."+domain) {
				continue
			}
			if len(domain) > len(best) || (len(domain) == len(best) && domain < best) {
				best, value = domain, mode
			}
		}
	}
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

func lessKube(a, b kube.Certificate) bool {
	if a.Fingerprint != b.Fingerprint {
		return a.Fingerprint < b.Fingerprint
	}
	return a.DedupKey < b.DedupKey
}

func ownerKey(entry owner.Owner) string {
	return entry.Value + "\x00" + string(entry.Source) + "\x00" + entry.Location
}

func sortedOwners(set map[string]owner.Owner) []owner.Owner {
	result := make([]owner.Owner, 0, len(set))
	for _, entry := range set {
		result = append(result, entry)
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

// Coverage statuses for one input source.
const (
	SourceStatusOK           = "ok"
	SourceStatusPartial      = "partial"
	SourceStatusFailed       = "failed"
	SourceStatusNotRequested = "not_requested"
)

// SourceCoverage is the health of one input source.
type SourceCoverage struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// Coverage reports how much of the requested inventory a scan actually checked,
// so a partial scan never looks clean.
//
// ratio is targets_probed / targets_requested rounded to four decimals, where
// targets_requested counts explicit and derived targets, including those
// dropped by the --max-hosts cap, and targets_probed counts probes that completed successfully. It is 1.0
// when no target was requested. Cap-truncated and wildcard names are counted
// separately in names_not_checked.
type Coverage struct {
	TargetsRequested int              `json:"targets_requested"`
	TargetsProbed    int              `json:"targets_probed"`
	TargetsFailed    int              `json:"targets_failed"`
	NamesNotChecked  int              `json:"names_not_checked"`
	Sources          []SourceCoverage `json:"sources"`
	Ratio            float64          `json:"ratio"`
}

// NewCoverage assembles a deterministic coverage report.
func NewCoverage(requested, probed, failed, notChecked int, sources []SourceCoverage) Coverage {
	sorted := append([]SourceCoverage(nil), sources...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	ratio := 1.0
	if requested > 0 {
		ratio = math.Round(float64(probed)/float64(requested)*10000) / 10000
		if ratio < 0 {
			ratio = 0
		}
		if ratio > 1 {
			ratio = 1
		}
	}
	return Coverage{
		TargetsRequested: requested,
		TargetsProbed:    probed,
		TargetsFailed:    failed,
		NamesNotChecked:  notChecked,
		Sources:          sorted,
		Ratio:            ratio,
	}
}
