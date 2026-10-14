// Package renewal classifies how a certificate is renewed and whether the
// configuration will keep up with shorter certificate lifetimes. It is pure: it
// never reads a clock and performs no I/O, so a fixed instant fully determines
// its output. Every value carries the evidence it is based on, and missing
// evidence is reported as unknown, never inferred from a name or an issuer
// alone. See docs/renewal.md and docs/adr/0006-roadmap-to-0.1.0.md (decisions 5
// and 6).
package renewal

import (
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/policy"
)

// Mode is how a certificate is renewed.
type Mode string

const (
	// ModeAutomatic means a managing controller renews the certificate.
	ModeAutomatic Mode = "automatic"
	// ModeManual means an operator declared that they renew it by hand.
	ModeManual Mode = "manual"
	// ModeUnknown means no renewal mechanism could be established.
	ModeUnknown Mode = "unknown"
)

// Health is the operational signal for an automatic renewal mechanism.
type Health string

const (
	// HealthHealthy means Ready=True and both renewalTime and notAfter are in
	// the future.
	HealthHealthy Health = "healthy"
	// HealthDegraded means a controller reported failure or a deadline passed.
	HealthDegraded Health = "degraded"
	// HealthConfigured means an automatic mechanism is present but no
	// operational signal confirms it works.
	HealthConfigured Health = "configured"
	// HealthUnknown means there is no automatic mechanism or no evidence.
	HealthUnknown Health = "unknown"
)

// Evidence sources. They are stable identifiers.
const (
	// SourceCertManager marks a fact read from a cert-manager Certificate.
	SourceCertManager = "cert-manager"
	// SourceCT marks a fact computed from Certificate Transparency.
	SourceCT = "ct"
	// SourceTLS marks a fact read from a live TLS handshake.
	SourceTLS = "tls"
	// SourceKubeSecret marks a fact read from a kubernetes.io/tls Secret.
	SourceKubeSecret = "kube-secret"
	// SourceConfig marks an explicit declaration in scadenza.yaml.
	SourceConfig = "config"
)

// Stable evidence fact keys.
const (
	FactIssuerType           = "issuer-type"
	FactACMEserver           = "acme-server"
	FactDuration             = "duration"
	FactRenewBefore          = "renew-before"
	FactReady                = "ready"
	FactStatusNotAfter       = "status-not-after"
	FactRenewalTime          = "renewal-time"
	FactRenewalModeDeclared  = "renewal-mode-declared"
	FactManagerAnnotation    = "cert-manager.io/certificate-name"
	FactNoManagingController = "no-managing-controller-found"
	FactCTIssuances365d      = "ct-issuances-365d"
	FactCTMedianIntervalDays = "ct-median-interval-days"
	FactRenewalOverdue       = "renewal-overdue"
	FactNotAfterPassed       = "not-after-passed"
	FactHealthCapped         = "health-capped-by-issuer-type"
)

// Risk kinds. They are stable finding kinds and each has a diagnostic page.
const (
	// KindRenewBeforeExceedsLifetime reports a fixed renewBefore at or beyond
	// the issued lifetime, which renews in a loop now.
	KindRenewBeforeExceedsLifetime = "renew-before-exceeds-lifetime"
	// KindRenewBeforeLoopAtNextLimit reports a fixed renewBefore that will loop
	// once the next shorter lifetime takes effect.
	KindRenewBeforeLoopAtNextLimit = "renew-before-loop-at-next-limit"
	// KindDurationExceedsNextLimit reports a requested duration larger than the
	// next CA/B maximum validity for a public ACME CA.
	KindDurationExceedsNextLimit = "duration-exceeds-next-limit"
	// KindRenewalDegraded reports degraded renewal health.
	KindRenewalDegraded = "renewal-degraded"
	// KindManualRenewalAfterLimit reports a manual renewal that falls after the
	// next CA/B step.
	KindManualRenewalAfterLimit = "manual-renewal-after-limit"
)

// OverlappedRenewalFraction is the fraction of a lifetime that cert-manager
// renews before expiry by default: 2/3 of the actual issued duration. Let's
// Encrypt recommends the same rough cadence. It is recorded as documentation of
// the recommendation, not used to compute a verdict.
//
// Sources:
//   - https://cert-manager.io/docs/usage/certificate/
//   - https://letsencrypt.org/2025/12/02/from-90-to-45
const OverlappedRenewalFraction = 2.0 / 3.0

// LetsEncryptDirectoryHost is the ACME directory host of the Let's Encrypt
// production endpoint.
const LetsEncryptDirectoryHost = "acme-v02.api.letsencrypt.org"

// letsEncryptSteps are the announced default-profile lifetimes of Let's
// Encrypt, after the 90-day default of today.
//
// Source: https://letsencrypt.org/2025/12/02/from-90-to-45
// VERIFY: the 64-day step date (announced as 2027-02-10) and the 45-day step
// date (2028-02-16) against the official post before relying on these dates.
// They are encoded here so a future date can be evaluated with --now.
var letsEncryptSteps = []struct {
	effective time.Time
	days      int
}{
	{time.Date(2027, 2, 10, 0, 0, 0, 0, time.UTC), 64},
	{time.Date(2028, 2, 16, 0, 0, 0, 0, time.UTC), 45},
}

// publicACMECA maps a known public ACME directory host to the CA it belongs to.
// Only a host in this table makes duration-exceeds-next-limit a finding; an
// unknown ACME server is reported as evidence and produces no finding, because
// a private CA may legitimately issue a longer lifetime.
//
// VERIFY: these directory hosts against each CA's current documentation before
// extending the table.
var publicACMECA = map[string]string{
	LetsEncryptDirectoryHost:   "Let's Encrypt",
	"acme.zerossl.com":         "ZeroSSL",
	"dv.acme-v02.api.pki.goog": "Google Trust Services",
	"pki.goog":                 "Google Trust Services",
	"api.buypass.com":          "Buypass",
}

// Evidence is one recorded fact behind a classification.
type Evidence struct {
	Source string `json:"source"`
	Fact   string `json:"fact"`
	Value  string `json:"value"`
}

// Risk is one configuration that will break under shorter lifetimes.
type Risk struct {
	Kind      string `json:"kind"`
	Detail    string `json:"detail"`
	Effective string `json:"effective,omitempty"`
}

// Classification is the renewal verdict for one certificate.
type Classification struct {
	Mode     Mode       `json:"mode"`
	Health   Health     `json:"health"`
	Evidence []Evidence `json:"evidence"`
	Risks    []Risk     `json:"risks"`
}

// Manager carries the cert-manager Certificate facts already read from the
// cluster. No new field is read for classification.
type Manager struct {
	IssuerType     string
	ACMEServer     string
	Duration       string
	RenewBefore    string
	StatusNotAfter string
	RenewalTime    string
	Ready          string
	ReadyReason    string
}

// Secret carries the cert-manager annotation of one kubernetes.io/tls Secret.
type Secret struct {
	// CertificateName is the cert-manager.io/certificate-name annotation value,
	// empty when the annotation is absent. An unmanaged TLS Secret has none.
	CertificateName string
}

// Issuance is one Certificate Transparency issuance for cadence evidence.
type Issuance struct {
	Names     []string
	NotBefore time.Time
}

// Input is the raw material for one certificate classification. Every field is
// a fact already gathered by the scan; nothing is inferred here.
type Input struct {
	Names     []string
	NotBefore time.Time
	NotAfter  time.Time
	Policy    policy.Assessment
	HasCT     bool
	HasLive   bool
	HasKube   bool

	// Manager is the cert-manager Certificate, when one was read.
	Manager *Manager
	// Secrets are the kubernetes.io/tls Secret observations.
	Secrets []Secret
	// CT is every Certificate Transparency issuance already fetched.
	CT []Issuance

	// DeclaredMode is an explicit scadenza.yaml declaration (manual).
	DeclaredMode Mode

	// Now is the evaluation instant, injected by the caller.
	Now time.Time
}

// Classify returns the renewal classification for one certificate. Precedence
// is: an automatic mechanism (cert-manager Certificate, then an annotated TLS
// Secret) wins over an explicit declaration, because the controller owns the
// renewal loop; a declaration is manual only when no mechanism was found.
func Classify(in Input) Classification {
	evidence := make([]Evidence, 0, 4)
	risks := make([]Risk, 0, 2)
	mode := ModeUnknown

	if in.DeclaredMode != "" {
		evidence = append(evidence, Evidence{Source: SourceConfig, Fact: FactRenewalModeDeclared, Value: string(in.DeclaredMode)})
	}

	// A Certificate resource is the renewal mechanism itself: cert-manager owns
	// the renewal loop for every issuer type it manages, so the mode is
	// automatic even when the issuer type cannot be resolved. An external or
	// unknown issuer type still caps health at configured because nothing
	// operational can be confirmed.
	// https://cert-manager.io/docs/usage/certificate/
	var manager *Manager
	hazardousIssuer := false
	if in.Manager != nil {
		manager = in.Manager
		issuerType := manager.IssuerType
		if issuerType == "" {
			issuerType = "unknown"
		}
		evidence = append(evidence, Evidence{Source: SourceCertManager, Fact: FactIssuerType, Value: issuerType})
		if manager.ACMEServer != "" {
			evidence = append(evidence, Evidence{Source: SourceCertManager, Fact: FactACMEserver, Value: manager.ACMEServer})
		}
		if manager.Duration != "" {
			evidence = append(evidence, Evidence{Source: SourceCertManager, Fact: FactDuration, Value: manager.Duration})
		}
		if manager.RenewBefore != "" {
			evidence = append(evidence, Evidence{Source: SourceCertManager, Fact: FactRenewBefore, Value: manager.RenewBefore})
		}
		if manager.Ready != "" {
			evidence = append(evidence, Evidence{Source: SourceCertManager, Fact: FactReady, Value: manager.Ready})
		}
		if manager.RenewalTime != "" {
			evidence = append(evidence, Evidence{Source: SourceCertManager, Fact: FactRenewalTime, Value: manager.RenewalTime})
		}
		if manager.StatusNotAfter != "" {
			evidence = append(evidence, Evidence{Source: SourceCertManager, Fact: FactStatusNotAfter, Value: manager.StatusNotAfter})
		}
		hazardousIssuer = issuerType == "external" || issuerType == "unknown"
		mode = ModeAutomatic
	}

	// A TLS Secret annotated by cert-manager is managed by it even when the
	// Certificate resource was not read (for example a missing CRD).
	annotated := ""
	for _, secret := range in.Secrets {
		if secret.CertificateName != "" && annotated == "" {
			annotated = secret.CertificateName
		}
	}
	if mode == ModeUnknown && annotated != "" {
		mode = ModeAutomatic
		evidence = append(evidence, Evidence{Source: SourceKubeSecret, Fact: FactManagerAnnotation, Value: annotated})
	}

	if mode == ModeUnknown && in.DeclaredMode == ModeManual {
		mode = ModeManual
	}

	// No managing controller was found. CT or TLS alone is never manual: it is
	// unknown, with the fact that proves why.
	if mode == ModeUnknown {
		source := SourceTLS
		switch {
		case len(in.Secrets) > 0:
			source = SourceKubeSecret
		case in.HasCT:
			source = SourceCT
		}
		evidence = append(evidence, Evidence{Source: source, Fact: FactNoManagingController, Value: "true"})
	}

	health, degradedReason := healthOf(in, manager, hazardousIssuer, &evidence)

	evidence = append(evidence, cadence(in)...)
	risks = append(risks, configRisks(in, manager)...)
	if health == HealthDegraded {
		risks = append(risks, Risk{Kind: KindRenewalDegraded, Detail: degradedReason})
	}
	if mode == ModeManual {
		risks = append(risks, manualRenewalRisk(in)...)
	}

	return Classification{
		Mode:     mode,
		Health:   health,
		Evidence: sortEvidence(evidence),
		Risks:    sortRisks(risks),
	}
}

// healthOf derives the renewal health, and returns the reason for a degraded
// verdict so the risk detail can repeat it.
func healthOf(in Input, manager *Manager, hazardousIssuer bool, evidence *[]Evidence) (Health, string) {
	if manager == nil {
		// Without a Certificate there is no operational signal: an annotated
		// Secret is configured, everything else is unknown.
		for _, secret := range in.Secrets {
			if secret.CertificateName != "" {
				return HealthConfigured, ""
			}
		}
		// Health describes an automatic mechanism; a manual renewal has no
		// mechanism scadenza can observe, so it is unknown.
		return HealthUnknown, ""
	}

	renewalTime, renewalErr := parseTime(manager.RenewalTime)
	statusNotAfter, notAfterErr := parseTime(manager.StatusNotAfter)
	now := in.Now
	statusMissing := manager.Ready == "" && manager.RenewalTime == "" && manager.StatusNotAfter == ""

	health := HealthConfigured
	reason := ""
	switch {
	case manager.Ready == "False":
		health = HealthDegraded
		reason = "Ready=False"
		if manager.ReadyReason != "" {
			reason += " (" + manager.ReadyReason + ")"
		}
	case renewalErr == nil && renewalTime.Add(time.Hour).Before(now):
		health = HealthDegraded
		reason = "renewal time " + manager.RenewalTime + " passed more than one hour ago"
	case notAfterErr == nil && statusNotAfter.Before(now):
		health = HealthDegraded
		reason = "status.notAfter " + manager.StatusNotAfter + " has passed"
	case statusMissing:
		health = HealthConfigured
	case manager.Ready == "True" && renewalErr == nil && renewalTime.After(now) && notAfterErr == nil && statusNotAfter.After(now):
		health = HealthHealthy
	}

	if health == HealthDegraded {
		switch {
		case strings.HasPrefix(reason, "renewal time"):
			*evidence = append(*evidence, Evidence{Source: SourceCertManager, Fact: FactRenewalOverdue, Value: manager.RenewalTime})
		case strings.HasPrefix(reason, "status.notAfter"):
			*evidence = append(*evidence, Evidence{Source: SourceCertManager, Fact: FactNotAfterPassed, Value: manager.StatusNotAfter})
		}
	}

	// An external or unknown issuer type still has cert-manager driving
	// renewal, but scadenza cannot confirm it works, so health is capped at
	// configured.
	if hazardousIssuer && health == HealthHealthy {
		health = HealthConfigured
		*evidence = append(*evidence, Evidence{Source: SourceCertManager, Fact: FactHealthCapped, Value: "configured"})
	}
	return health, reason
}

// cadence returns the Certificate Transparency cadence evidence for the
// certificate's name set. It is evidence only, never a classification.
func cadence(in Input) []Evidence {
	names := map[string]bool{}
	for _, name := range in.Names {
		names[normalizeName(name)] = true
	}
	instants := []time.Time{}
	recent := 0
	cutoff := in.Now.AddDate(-1, 0, 0)
	for _, issuance := range in.CT {
		if issuance.NotBefore.IsZero() || !intersects(issuance.Names, names) {
			continue
		}
		instants = append(instants, issuance.NotBefore)
		if !issuance.NotBefore.Before(cutoff) {
			recent++
		}
	}
	if len(instants) == 0 {
		return nil
	}
	sort.SliceStable(instants, func(i, j int) bool { return instants[i].Before(instants[j]) })
	result := []Evidence{{Source: SourceCT, Fact: FactCTIssuances365d, Value: strconv.Itoa(recent)}}
	if median, ok := medianIntervalDays(instants); ok {
		result = append(result, Evidence{Source: SourceCT, Fact: FactCTMedianIntervalDays, Value: strconv.Itoa(median)})
	}
	return result
}

// configRisks returns the findings that come from the certificate's own
// configuration: a fixed renewBefore and a requested duration.
func configRisks(in Input, manager *Manager) []Risk {
	if manager == nil {
		return nil
	}
	risks := []Risk{}
	renewBefore, hasRenewBefore := parseDuration(manager.RenewBefore)
	lifetime := in.NotAfter.Sub(in.NotBefore)

	if hasRenewBefore && lifetime > 0 && renewBefore >= lifetime {
		risks = append(risks, Risk{
			Kind: KindRenewBeforeExceedsLifetime,
			Detail: "spec.renewBefore " + manager.RenewBefore + " is not shorter than the issued lifetime " +
				lifetime.String() + "; cert-manager renews in a loop. Set spec.renewBeforePercentage instead.",
		})
	}

	if hasRenewBefore {
		best := ""
		detail := ""
		if in.Policy.NextLimitEffective != "" && renewBefore >= time.Duration(in.Policy.NextLimitDays)*24*time.Hour {
			best = in.Policy.NextLimitEffective
			detail = "spec.renewBefore " + manager.RenewBefore + " reaches the next CA/B maximum validity of " +
				strconv.Itoa(in.Policy.NextLimitDays) + " days"
		}
		if effective, days, ok := letsEncryptNextStep(manager.ACMEServer, in.Now); ok && renewBefore >= time.Duration(days)*24*time.Hour {
			if best == "" || effective < best {
				best = effective
				detail = "spec.renewBefore " + manager.RenewBefore + " reaches the next Let's Encrypt lifetime of " +
					strconv.Itoa(days) + " days"
			}
		}
		if best != "" {
			risks = append(risks, Risk{
				Kind:      KindRenewBeforeLoopAtNextLimit,
				Detail:    detail + " (effective " + best + "); renewal loops after that date. Set spec.renewBeforePercentage.",
				Effective: best,
			})
		}
	}

	if duration, ok := parseDuration(manager.Duration); ok && manager.IssuerType == "acme" && in.Policy.NextLimitEffective != "" {
		host := directoryHost(manager.ACMEServer)
		if ca, known := publicACMECA[host]; known && duration > time.Duration(in.Policy.NextLimitDays)*24*time.Hour {
			risks = append(risks, Risk{
				Kind: KindDurationExceedsNextLimit,
				Detail: "spec.duration " + manager.Duration + " exceeds the next CA/B maximum validity of " +
					strconv.Itoa(in.Policy.NextLimitDays) + " days for public ACME CA " + ca + "; the CA will issue a shorter lifetime.",
				Effective: in.Policy.NextLimitEffective,
			})
		}
	}
	return risks
}

// manualRenewalRisk reports a manual certificate whose next renewal falls after
// the next CA/B step, when the manual workload grows.
func manualRenewalRisk(in Input) []Risk {
	if in.Policy.NextLimitEffective == "" || in.NotAfter.IsZero() {
		return nil
	}
	effective, err := parseTime(in.Policy.NextLimitEffective)
	if err != nil || !in.NotAfter.After(effective) {
		return nil
	}
	return []Risk{{
		Kind: KindManualRenewalAfterLimit,
		Detail: "manual renewal is due " + in.NotAfter.UTC().Format(time.RFC3339) + ", after the next CA/B maximum validity of " +
			strconv.Itoa(in.Policy.NextLimitDays) + " days (effective " + in.Policy.NextLimitEffective + "); manual renewal workload grows.",
		Effective: in.Policy.NextLimitEffective,
	}}
}

// letsEncryptNextStep returns the next announced Let's Encrypt lifetime step
// strictly after now, but only for the Let's Encrypt production directory.
func letsEncryptNextStep(server string, now time.Time) (string, int, bool) {
	if directoryHost(server) != LetsEncryptDirectoryHost {
		return "", 0, false
	}
	for _, step := range letsEncryptSteps {
		if step.effective.After(now) {
			return step.effective.UTC().Format(time.RFC3339), step.days, true
		}
	}
	return "", 0, false
}

// directoryHost extracts the host of an ACME directory URL. An unparsable or
// empty value yields an empty host, which matches no known CA.
func directoryHost(server string) string {
	trimmed := strings.TrimSpace(server)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Hostname() == "" {
		return trimmed
	}
	return parsed.Hostname()
}

// medianIntervalDays returns the median number of days between consecutive
// issuances, rounded to the nearest whole day.
func medianIntervalDays(instants []time.Time) (int, bool) {
	if len(instants) < 2 {
		return 0, false
	}
	intervals := make([]float64, 0, len(instants)-1)
	for index := 1; index < len(instants); index++ {
		intervals = append(intervals, instants[index].Sub(instants[index-1]).Hours()/24)
	}
	sort.Float64s(intervals)
	middle := len(intervals) / 2
	median := intervals[middle]
	if len(intervals)%2 == 0 {
		median = (intervals[middle-1] + intervals[middle]) / 2
	}
	return int(math.Round(median)), true
}

// parseDuration parses a cert-manager spec duration such as "2160h0m0s".
func parseDuration(value string) (time.Duration, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, false
	}
	parsed, err := time.ParseDuration(trimmed)
	if err != nil || parsed <= 0 {
		return 0, false
	}
	return parsed, true
}

// parseTime parses an RFC 3339 timestamp as written in a Kubernetes status.
func parseTime(value string) (time.Time, error) {
	return time.Parse(time.RFC3339, strings.TrimSpace(value))
}

func intersects(names []string, set map[string]bool) bool {
	for _, name := range names {
		if set[normalizeName(name)] {
			return true
		}
	}
	return false
}

func normalizeName(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func sortEvidence(items []Evidence) []Evidence {
	result := append([]Evidence(nil), items...)
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Source != result[j].Source {
			return result[i].Source < result[j].Source
		}
		if result[i].Fact != result[j].Fact {
			return result[i].Fact < result[j].Fact
		}
		return result[i].Value < result[j].Value
	})
	return result
}

func sortRisks(items []Risk) []Risk {
	result := append([]Risk(nil), items...)
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}
		if result[i].Effective != result[j].Effective {
			return result[i].Effective < result[j].Effective
		}
		return result[i].Detail < result[j].Detail
	})
	return result
}
