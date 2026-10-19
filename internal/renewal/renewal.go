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
	// SourceKeyVault marks a fact read from an Azure Key Vault certificate policy.
	SourceKeyVault = "keyvault"
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
	FactKeyVaultIssuer       = "issuer"
	FactKeyVaultValidity     = "policy-validity-months"
	FactKeyVaultAutoRenew    = "auto-renew"
	FactKeyVaultEmail        = "email-contacts"
	FactKeyVaultNoActions    = "no-lifetime-actions"
	FactDurationSource       = "duration-source"
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
	// KindRenewalConfigInvalid reports a spec.duration, spec.renewBefore, or
	// spec.renewBeforePercentage value that cert-manager itself rejects.
	KindRenewalConfigInvalid                = "renewal-config-invalid"
	KindKeyVaultValidityExceedsNextLimit    = "keyvault-validity-exceeds-next-limit"
	KindKeyVaultRenewTriggerExceedsLifetime = "keyvault-renew-trigger-exceeds-lifetime"
)

// cert-manager's own validity constraints on a Certificate spec. A value that
// violates one of them is rejected by the API server, so it is reported as the
// distinct renewal-config-invalid risk rather than folded into a lifetime risk.
//
// Source: https://cert-manager.io/docs/usage/certificate/
const (
	// minimumDuration is the smallest accepted spec.duration.
	minimumDuration = time.Hour
	// minimumRenewBefore is the smallest accepted effective renewBefore.
	minimumRenewBefore = 5 * time.Minute
	// defaultDuration is the documented cert-manager default applied when
	// spec.duration is absent: 90 days.
	defaultDuration = 90 * 24 * time.Hour
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
	IssuerType            string
	ACMEServer            string
	Duration              string
	RenewBefore           string
	RenewBeforePercentage string
	StatusNotAfter        string
	RenewalTime           string
	Ready                 string
	ReadyReason           string
}

// Secret carries the cert-manager annotation of one kubernetes.io/tls Secret.
type Secret struct {
	// CertificateName is the cert-manager.io/certificate-name annotation value,
	// empty when the annotation is absent. An unmanaged TLS Secret has none.
	CertificateName string
}

// LifetimeAction is a Key Vault policy lifetime action.
type LifetimeAction struct {
	Type               string
	DaysBeforeExpiry   *int
	LifetimePercentage *int
}

// KeyVault is the certificate policy evidence read from Azure Key Vault.
type KeyVault struct {
	Issuer          string
	ValidityMonths  *int
	LifetimeActions []LifetimeAction
}

// Issuance is one Certificate Transparency issuance for cadence evidence. The
// identity fields let cadence collapse the precertificate and the final
// certificate of the same issuance, and the duplicate records that overlapping
// domain queries return.
type Issuance struct {
	Names       []string
	NotBefore   time.Time
	Issuer      string
	Fingerprint string
	Serial      string
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
	// KeyVault is the Azure Key Vault certificate policy, when one was read.
	KeyVault *KeyVault
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

	// Key Vault policy facts are direct evidence. AutoRenew with an integrated
	// public issuer is automatic; EmailContacts alone is manual evidence.
	// https://learn.microsoft.com/en-us/azure/key-vault/certificates/tutorial-rotate-certificates
	// https://learn.microsoft.com/en-us/azure/key-vault/certificates/how-to-integrate-certificate-authority
	autoRenew := false
	emailOnlyActions := true
	if in.KeyVault != nil {
		issuer := in.KeyVault.Issuer
		if issuer == "" {
			issuer = "Unknown"
		}
		evidence = append(evidence, Evidence{Source: SourceKeyVault, Fact: FactKeyVaultIssuer, Value: issuer})
		if in.KeyVault.ValidityMonths != nil {
			evidence = append(evidence, Evidence{
				Source: SourceKeyVault,
				Fact:   FactKeyVaultValidity,
				Value:  strconv.Itoa(*in.KeyVault.ValidityMonths),
			})
		}
		if len(in.KeyVault.LifetimeActions) == 0 {
			emailOnlyActions = false
			evidence = append(evidence, Evidence{Source: SourceKeyVault, Fact: FactKeyVaultNoActions, Value: "true"})
		}
		for _, action := range in.KeyVault.LifetimeActions {
			switch normalizeKeyVaultAction(action.Type) {
			case "autorenew":
				autoRenew = true
				emailOnlyActions = false
				evidence = append(evidence, Evidence{Source: SourceKeyVault, Fact: FactKeyVaultAutoRenew, Value: action.Type})
			case "emailcontacts":
				evidence = append(evidence, Evidence{Source: SourceKeyVault, Fact: FactKeyVaultEmail, Value: action.Type})
			default:
				emailOnlyActions = false
			}
		}
		if autoRenew && isIntegratedIssuer(issuer) {
			mode = ModeAutomatic
		} else if !autoRenew && emailOnlyActions && len(in.KeyVault.LifetimeActions) > 0 {
			mode = ModeManual
		}
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
		if strings.TrimSpace(manager.Duration) != "" {
			evidence = append(evidence, Evidence{Source: SourceCertManager, Fact: FactDuration, Value: manager.Duration})
		} else {
			evidence = append(evidence, Evidence{Source: SourceCertManager, Fact: FactDurationSource, Value: "default"})
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
	if mode == ModeUnknown && in.KeyVault == nil {
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
	risks = append(risks, keyVaultRisks(in)...)
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
		// Key Vault AutoRenew is configured, but the policy has no operational
		// health signal beyond the configuration itself.
		if in.KeyVault != nil && keyVaultAutoRenew(in.KeyVault) && isIntegratedIssuer(in.KeyVault.Issuer) {
			return HealthConfigured, ""
		}
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
// certificate's name set. It is evidence only, never a classification. Records
// are first deduplicated by stable issuance identity, so a precertificate and
// its final certificate, or the duplicate records that overlapping domain
// queries return, count once. The 365-day window is a fixed 365*24h ending at
// the evaluation instant, and a record issued after that instant is ignored.
func cadence(in Input) []Evidence {
	names := map[string]bool{}
	for _, name := range in.Names {
		names[normalizeName(name)] = true
	}
	seen := map[string]bool{}
	instants := []time.Time{}
	recent := 0
	cutoff := in.Now.Add(-365 * 24 * time.Hour)
	for _, issuance := range in.CT {
		if issuance.NotBefore.IsZero() || issuance.NotBefore.After(in.Now) || !intersects(issuance.Names, names) {
			continue
		}
		identity := issuanceIdentity(issuance)
		if seen[identity] {
			continue
		}
		seen[identity] = true
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
// configuration: values cert-manager rejects, a fixed renewBefore that loops
// against the issued lifetime, and a requested duration or renewBefore that
// reaches a shorter lifetime. Renewal-specific CA/B decisions use the
// evaluation instant, so a step that already took effect is never reported with
// a stale date.
func configRisks(in Input, manager *Manager) []Risk {
	if manager == nil {
		return nil
	}
	risks := []Risk{}
	lifetime := in.NotAfter.Sub(in.NotBefore)

	rawDuration := strings.TrimSpace(manager.Duration)
	duration, durationErr := time.ParseDuration(rawDuration)
	hasDuration := rawDuration != ""
	switch {
	case hasDuration && durationErr != nil:
		risks = append(risks, invalidConfigRisk("spec.duration "+manager.Duration+" is not a valid duration"))
	case hasDuration && duration < minimumDuration:
		risks = append(risks, invalidConfigRisk("spec.duration "+manager.Duration+" is below cert-manager's 1h minimum"))
	}

	rawRenewBefore := strings.TrimSpace(manager.RenewBefore)
	renewBefore, renewBeforeErr := time.ParseDuration(rawRenewBefore)
	hasRenewBefore := rawRenewBefore != ""
	switch {
	case hasRenewBefore && renewBeforeErr != nil:
		risks = append(risks, invalidConfigRisk("spec.renewBefore "+manager.RenewBefore+" is not a valid duration"))
	case hasRenewBefore && renewBefore < minimumRenewBefore:
		risks = append(risks, invalidConfigRisk("spec.renewBefore "+manager.RenewBefore+" is below cert-manager's 5m minimum"))
	}

	// spec.duration must be greater than spec.renewBefore; equal is rejected.
	if hasDuration && durationErr == nil && hasRenewBefore && renewBeforeErr == nil && duration <= renewBefore {
		risks = append(risks, invalidConfigRisk("spec.duration "+manager.Duration+" must be greater than spec.renewBefore "+manager.RenewBefore))
	}

	// spec.renewBeforePercentage is an integer percentage of the actual issued
	// lifetime, between 1 and 99, whose result is the effective renewBefore.
	rawPercentage := strings.TrimSpace(manager.RenewBeforePercentage)
	percentage, percentageErr := strconv.Atoi(rawPercentage)
	hasPercentage := rawPercentage != ""
	switch {
	case hasPercentage && (percentageErr != nil || percentage < 1 || percentage > 99):
		risks = append(risks, invalidConfigRisk("spec.renewBeforePercentage "+manager.RenewBeforePercentage+" must be an integer percentage between 1 and 99"))
	case hasPercentage && lifetime > 0:
		effective := time.Duration(float64(lifetime) * float64(percentage) / 100)
		if effective < minimumRenewBefore {
			risks = append(risks, invalidConfigRisk("spec.renewBeforePercentage "+manager.RenewBeforePercentage+" yields an effective renewBefore of "+
				effective.String()+", below cert-manager's 5m minimum"))
		}
	}

	// A fixed renewBefore at or beyond the actual issued lifetime renews in a
	// loop now. spec.renewBeforePercentage follows the issued lifetime, so it
	// never triggers this check.
	if hasRenewBefore && renewBeforeErr == nil && lifetime > 0 && renewBefore >= lifetime {
		risks = append(risks, Risk{
			Kind: KindRenewBeforeExceedsLifetime,
			Detail: "spec.renewBefore " + manager.RenewBefore + " is not shorter than the issued lifetime " +
				lifetime.String() + "; cert-manager renews in a loop. Set spec.renewBeforePercentage instead.",
		})
	}

	// A fixed renewBefore at or beyond the next shorter lifetime starts looping
	// once that step takes effect.
	if hasRenewBefore && renewBeforeErr == nil {
		limitDays, limitEffective := renewalLimits(in.Now)
		best := ""
		detail := ""
		if limitEffective != "" && renewBefore >= time.Duration(limitDays)*24*time.Hour {
			best = limitEffective
			detail = "spec.renewBefore " + manager.RenewBefore + " reaches the next CA/B maximum validity of " +
				strconv.Itoa(limitDays) + " days"
		}
		if effective, days, ok := letsEncryptNextStep(manager.ACMEServer, in.Now); ok && renewBefore >= time.Duration(days)*24*time.Hour {
			if best == "" || effective < best {
				best = effective
				detail = "spec.renewBefore " + manager.RenewBefore + " reaches the next announced Let's Encrypt lifetime of " +
					strconv.Itoa(days) + " days (announced, not confirmed)"
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

	// The requested duration is compared with the CA/B maximum validity that
	// governs the next issuance. When spec.duration is absent, cert-manager's
	// documented 90-day default applies.
	if manager.IssuerType == "acme" {
		if ca, known := publicACMECA[directoryHost(manager.ACMEServer)]; known {
			effectiveDuration := defaultDuration
			if hasDuration && durationErr == nil {
				effectiveDuration = duration
			}
			limitDays, limitEffective := renewalLimits(in.Now)
			if effectiveDuration > time.Duration(limitDays)*24*time.Hour {
				risks = append(risks, Risk{
					Kind: KindDurationExceedsNextLimit,
					Detail: "spec.duration " + durationLabel(manager.Duration) + " exceeds " + caLimitPhrase(limitDays, limitEffective) +
						" for public ACME CA " + ca + "; the CA will issue a shorter lifetime.",
					Effective: limitEffective,
				})
			}
		}
	}
	return risks
}

// keyVaultRisks reports Key Vault policy configurations that will break under
// shorter public certificate lifetimes.
func keyVaultRisks(in Input) []Risk {
	if in.KeyVault == nil {
		return nil
	}
	risks := []Risk{}
	if in.KeyVault.ValidityMonths != nil && in.Policy.NextLimitEffective != "" {
		validityDays := int(math.Round(float64(*in.KeyVault.ValidityMonths) * 30.4))
		if validityDays > in.Policy.NextLimitDays {
			risks = append(risks, Risk{
				Kind: KindKeyVaultValidityExceedsNextLimit,
				Detail: "certificate policy validity " + strconv.Itoa(*in.KeyVault.ValidityMonths) +
					" months (" + strconv.Itoa(validityDays) + " days at 30.4 days per month) exceeds the next CA/B maximum of " +
					strconv.Itoa(in.Policy.NextLimitDays) + " days.",
				Effective: in.Policy.NextLimitEffective,
			})
		}
	}
	if keyVaultAutoRenew(in.KeyVault) && in.KeyVault.ValidityMonths != nil {
		lifetimeDays := int(math.Round(float64(*in.KeyVault.ValidityMonths) * 30.4))
		for _, action := range in.KeyVault.LifetimeActions {
			if !strings.EqualFold(strings.ReplaceAll(action.Type, "_", ""), "AutoRenew") {
				continue
			}
			if action.DaysBeforeExpiry != nil && *action.DaysBeforeExpiry >= lifetimeDays {
				risks = append(risks, Risk{
					Kind:   KindKeyVaultRenewTriggerExceedsLifetime,
					Detail: "AutoRenew triggers " + strconv.Itoa(*action.DaysBeforeExpiry) + " days before expiry, at or beyond the " + strconv.Itoa(lifetimeDays) + "-day policy lifetime.",
				})
			}
			if action.LifetimePercentage != nil && *action.LifetimePercentage >= 100 {
				risks = append(risks, Risk{
					Kind:   KindKeyVaultRenewTriggerExceedsLifetime,
					Detail: "AutoRenew triggers at " + strconv.Itoa(*action.LifetimePercentage) + "% of lifetime, at or beyond the certificate lifetime.",
				})
			}
		}
	}
	return risks
}

func keyVaultAutoRenew(policy *KeyVault) bool {
	if policy == nil {
		return false
	}
	for _, action := range policy.LifetimeActions {
		if normalizeKeyVaultAction(action.Type) == "autorenew" {
			return true
		}
	}
	return false
}

func normalizeKeyVaultAction(value string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "_", ""))
}

func isIntegratedIssuer(value string) bool {
	issuer := strings.ToLower(strings.TrimSpace(value))
	return issuer != "" && issuer != "self" && issuer != "unknown"
}

// manualRenewalRisk reports a manual certificate whose next renewal falls after
// the next CA/B step, when the manual workload grows.
func manualRenewalRisk(in Input) []Risk {
	if in.NotAfter.IsZero() {
		return nil
	}
	limitDays, limitEffective := renewalLimits(in.Now)
	if limitEffective == "" {
		return nil
	}
	effective, err := parseTime(limitEffective)
	if err != nil || !in.NotAfter.After(effective) {
		return nil
	}
	return []Risk{{
		Kind: KindManualRenewalAfterLimit,
		Detail: "manual renewal is due " + in.NotAfter.UTC().Format(time.RFC3339) + ", after the next CA/B maximum validity of " +
			strconv.Itoa(limitDays) + " days (effective " + limitEffective + "); manual renewal workload grows.",
		Effective: limitEffective,
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

// invalidConfigRisk is a value cert-manager's own validation rejects, so the
// Certificate could not be applied as written.
func invalidConfigRisk(detail string) Risk {
	return Risk{Kind: KindRenewalConfigInvalid, Detail: detail + "; cert-manager rejects this certificate"}
}

// renewalLimits returns the CA/B maximum validity that governs the next
// issuance: the next scheduled step strictly after now, so a step that already
// took effect is never reported with a stale date, or the step in force at now
// when no further step remains.
func renewalLimits(now time.Time) (int, string) {
	if effective, limits, ok := policy.NextStepAfter(now); ok {
		return limits.MaxValidityDays, effective.UTC().Format(time.RFC3339)
	}
	return policy.MaxValidityAt(now), ""
}

// caLimitPhrase names a CA/B limit, saying whether it is the next scheduled step
// or the one already in force.
func caLimitPhrase(days int, effective string) string {
	if effective != "" {
		return "the next CA/B maximum validity of " + strconv.Itoa(days) + " days (effective " + effective + ")"
	}
	return "the current CA/B maximum validity of " + strconv.Itoa(days) + " days"
}

// durationLabel names the duration a risk is about, naming the documented
// default when spec.duration is absent.
func durationLabel(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unset (cert-manager default 90 days)"
	}
	return value
}

// issuanceIdentity is the stable identity of one issuance. A precertificate and
// its final certificate share the issuer and serial, so serial (with issuer)
// wins; a record with no serial falls back to its fingerprint, then to its name
// set and notBefore.
func issuanceIdentity(issuance Issuance) string {
	if serial := strings.ToLower(strings.TrimSpace(issuance.Serial)); serial != "" {
		return "serial:" + normalizeName(issuance.Issuer) + "|" + serial
	}
	if fingerprint := strings.ToLower(strings.TrimSpace(issuance.Fingerprint)); fingerprint != "" {
		return "fp:" + fingerprint
	}
	names := make([]string, 0, len(issuance.Names))
	for _, name := range issuance.Names {
		names = append(names, normalizeName(name))
	}
	sort.Strings(names)
	return "names:" + strings.Join(names, ",") + "|" + issuance.NotBefore.UTC().Format(time.RFC3339)
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
