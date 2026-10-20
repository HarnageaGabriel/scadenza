package policy

import (
	"testing"
)

// TestNextStepAfterIsStrictlyAfter pins the boundary of the schedule lookup:
// a step that takes effect exactly at the given instant is the one in force,
// never the next one, so the next step is the one after it.
//
// Promise: policy.NextStepAfter returns "the first schedule step strictly
// after t" and reports ok=false at or after the last step.
func TestNextStepAfterIsStrictlyAfter(t *testing.T) {
	cases := []struct {
		name          string
		instant       string
		wantEffective string
		wantDays      int
		wantOK        bool
	}{
		{
			name:          "one second before the 2026 step the 2026 step is next",
			instant:       "2026-03-14T23:59:59Z",
			wantEffective: "2026-03-15T00:00:00Z",
			wantDays:      200,
			wantOK:        true,
		},
		{
			name:          "exactly at the 2026 step the 2027 step is next",
			instant:       "2026-03-15T00:00:00Z",
			wantEffective: "2027-03-15T00:00:00Z",
			wantDays:      100,
			wantOK:        true,
		},
		{
			name:          "exactly at the 2027 step the 2029 step is next",
			instant:       "2027-03-15T00:00:00Z",
			wantEffective: "2029-03-15T00:00:00Z",
			wantDays:      47,
			wantOK:        true,
		},
		{
			name:    "exactly at the last step there is no next step",
			instant: "2029-03-15T00:00:00Z",
			wantOK:  false,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			effective, limits, ok := NextStepAfter(mustTime(t, test.instant))
			if ok != test.wantOK {
				t.Fatalf("ok = %v, want %v", ok, test.wantOK)
			}
			if !test.wantOK {
				return
			}
			if !effective.Equal(mustTime(t, test.wantEffective)) {
				t.Fatalf("effective = %s, want %s", effective.Format("2006-01-02T15:04:05Z"), test.wantEffective)
			}
			if limits.MaxValidityDays != test.wantDays {
				t.Fatalf("max validity = %d, want %d", limits.MaxValidityDays, test.wantDays)
			}
		})
	}
}

// TestAssessLimitsAreInclusive pins the inclusive boundary of the dated
// limits: a lifetime of exactly the maximum validity fits, one day more does
// not, both for the limit in force at issuance and for the next limit.
//
// Promise: policy.Assess ("compliant_at_issuance is true when the exact
// lifetime is at or below the maximum validity in force at issuance",
// "fits_next_limit is true when the lifetime also fits the next scheduled
// limit").
func TestAssessLimitsAreInclusive(t *testing.T) {
	notBefore := mustTime(t, "2026-06-01T00:00:00Z")
	cases := []struct {
		name          string
		days          int
		wantFits      bool
		wantCompliant bool
	}{
		{"a lifetime of exactly the 100-day next limit fits", 100, true, true},
		{"a lifetime of one day more than the next limit does not fit", 101, false, true},
		{"a lifetime of exactly the 200-day maximum at issuance is compliant", 200, false, true},
		{"a lifetime of one day more than the maximum at issuance is not compliant", 201, false, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			assessment := Assess(notBefore, day(notBefore, test.days))
			if assessment.FitsNextLimit != test.wantFits {
				t.Fatalf("fits next limit = %v, want %v (%+v)", assessment.FitsNextLimit, test.wantFits, assessment)
			}
			if assessment.CompliantAtIssuance != test.wantCompliant {
				t.Fatalf("compliant at issuance = %v, want %v (%+v)", assessment.CompliantAtIssuance, test.wantCompliant, assessment)
			}
			if assessment.NextLimitDays != 100 || assessment.NextLimitEffective != "2027-03-15T00:00:00Z" {
				t.Fatalf("next limit = %d %q, want 100 days effective 2027-03-15", assessment.NextLimitDays, assessment.NextLimitEffective)
			}
			if assessment.MaxValidityAtIssuanceDays != 200 {
				t.Fatalf("max validity at issuance = %d, want 200", assessment.MaxValidityAtIssuanceDays)
			}
		})
	}
}
