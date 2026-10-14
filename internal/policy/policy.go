// Package policy encodes the dated certificate lifetime and domain validation
// (DCV) reuse limits from the CA/Browser Forum Baseline Requirements and the
// SC-081 phased schedule. It is pure: it never reads a clock and performs no
// I/O, so a fixed instant fully determines its output.
package policy

import "time"

// Effective dates of the SC-081 validity and DCV-reuse steps.
//
// Source: CA/Browser Forum Baseline Requirements, SC-081v3 (adopted 2025),
// which schedules a maximum certificate validity and a maximum DCV reuse of
// 200 days from 2026-03-15, 100 days from 2027-03-15, and 47/10 days from
// 2029-03-15. Before 2026-03-15 the BRs allowed a 398-day validity (BR 6.3.2)
// and 398-day DCV reuse (BR 4.2.1).
// VERIFY: confirm each effective date and the pre-2026 398-day values against
// the published SC-081 ballot and the BR change history.
var (
	// Effective200Days is when the 200/200-day limits take effect.
	Effective200Days = time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)
	// Effective100Days is when the 100/100-day limits take effect.
	Effective100Days = time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC)
	// Effective47Days is when the 47-day validity and 10-day DCV reuse limits
	// take effect.
	Effective47Days = time.Date(2029, 3, 15, 0, 0, 0, 0, time.UTC)
)

// BackdateTolerance is how far a certificate notBefore may precede the actual
// issuance instant. A CA may backdate notBefore by up to 24 hours, so a
// certificate is assessed against the most permissive limit in force anywhere
// in [notBefore, notBefore+BackdateTolerance]. VERIFY: confirm the exact BR
// backdating allowance before tightening this tolerance.
const BackdateTolerance = 24 * time.Hour

// Limits are the maximum certificate validity and DCV reuse in whole days.
type Limits struct {
	MaxValidityDays int
	DCVReuseDays    int
}

// schedule is ordered by effective date; the first entry is the pre-2026 base.
var schedule = []struct {
	effective time.Time
	limits    Limits
}{
	{time.Time{}, Limits{MaxValidityDays: 398, DCVReuseDays: 398}},
	{Effective200Days, Limits{MaxValidityDays: 200, DCVReuseDays: 200}},
	{Effective100Days, Limits{MaxValidityDays: 100, DCVReuseDays: 100}},
	{Effective47Days, Limits{MaxValidityDays: 47, DCVReuseDays: 10}},
}

// LimitsAt returns the limits in force at instant t.
func LimitsAt(t time.Time) Limits {
	result := schedule[0].limits
	for _, step := range schedule {
		if !t.Before(step.effective) {
			result = step.limits
		}
	}
	return result
}

// MaxValidityAt returns the maximum certificate validity in days at t.
func MaxValidityAt(t time.Time) int { return LimitsAt(t).MaxValidityDays }

// DCVReuseAt returns the maximum domain validation reuse period in days at t.
func DCVReuseAt(t time.Time) int { return LimitsAt(t).DCVReuseDays }

// NextStepAfter returns the first schedule step strictly after t. ok is false
// when t is at or after the last step, so there is no future limit.
func NextStepAfter(t time.Time) (time.Time, Limits, bool) {
	for _, step := range schedule {
		if step.effective.After(t) {
			return step.effective, step.limits, true
		}
	}
	return time.Time{}, Limits{}, false
}

// Assessment is the per-certificate policy evaluation. Field names and JSON
// tags are part of the stable output contract.
type Assessment struct {
	MaxValidityAtIssuanceDays int    `json:"max_validity_at_issuance_days"`
	CompliantAtIssuance       bool   `json:"compliant_at_issuance"`
	NextLimitDays             int    `json:"next_limit_days"`
	NextLimitEffective        string `json:"next_limit_effective"`
	FitsNextLimit             bool   `json:"fits_next_limit"`
}

// Assess evaluates one certificate against the dated validity limits.
//
// compliant_at_issuance is true when the exact lifetime (notAfter - notBefore)
// is at or below the maximum validity in force at issuance. Because notBefore
// may be backdated, the most permissive limit within [notBefore,
// notBefore+BackdateTolerance] is used; this never reports a certificate that
// was compliant when its CA signed it as non-compliant. fits_next_limit is
// true when the lifetime also fits the next scheduled limit; when no further
// step exists it equals compliant_at_issuance and next_limit_effective is "".
func Assess(notBefore, notAfter time.Time) Assessment {
	if notBefore.IsZero() || notAfter.IsZero() || notAfter.Before(notBefore) {
		return Assessment{}
	}
	maxAtIssuance := MaxValidityAt(notBefore)
	if tolerant := MaxValidityAt(notBefore.Add(BackdateTolerance)); tolerant > maxAtIssuance {
		maxAtIssuance = tolerant
	}
	lifetime := notAfter.Sub(notBefore)
	compliant := lifetime <= time.Duration(maxAtIssuance)*24*time.Hour

	assessment := Assessment{
		MaxValidityAtIssuanceDays: maxAtIssuance,
		CompliantAtIssuance:       compliant,
		NextLimitDays:             maxAtIssuance,
		FitsNextLimit:             compliant,
	}
	if effective, limits, ok := NextStepAfter(notBefore); ok {
		assessment.NextLimitDays = limits.MaxValidityDays
		assessment.NextLimitEffective = effective.UTC().Format(time.RFC3339)
		assessment.FitsNextLimit = lifetime <= time.Duration(limits.MaxValidityDays)*24*time.Hour
	}
	return assessment
}
