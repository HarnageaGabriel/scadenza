package policy

import (
	"testing"
	"time"
)

func day(t time.Time, days int) time.Time { return t.AddDate(0, 0, days) }

func TestLimitsAreDated(t *testing.T) {
	// Sources: CA/Browser Forum Baseline Requirements and SC-081v3. The
	// boundary instants are the 2026/2027/2029 effective dates.
	cases := []struct {
		name    string
		instant string
		want    Limits
	}{
		{"pre-2018", "2017-06-01T00:00:00Z", Limits{1186, 398}},
		{"last second before 2018 step", "2018-02-28T23:59:59Z", Limits{1186, 398}},
		{"2018 step", "2018-03-01T00:00:00Z", Limits{825, 398}},
		{"last second before 2020 step", "2020-08-31T23:59:59Z", Limits{825, 398}},
		{"2020 step", "2020-09-01T00:00:00Z", Limits{398, 398}},
		{"pre-2026", "2025-06-01T00:00:00Z", Limits{398, 398}},
		{"just before 2026 step", "2026-03-14T23:59:59Z", Limits{398, 398}},
		{"2026 step", "2026-03-15T00:00:00Z", Limits{200, 200}},
		{"just before 2027 step", "2027-03-14T23:59:59Z", Limits{200, 200}},
		{"2027 step", "2027-03-15T00:00:00Z", Limits{100, 100}},
		{"just before 2029 step", "2029-03-14T23:59:59Z", Limits{100, 100}},
		{"2029 step", "2029-03-15T00:00:00Z", Limits{47, 10}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			instant := mustTime(t, test.instant)
			if got := MaxValidityAt(instant); got != test.want.MaxValidityDays {
				t.Errorf("MaxValidityAt(%s) = %d, want %d", test.instant, got, test.want.MaxValidityDays)
			}
			if got := DCVReuseAt(instant); got != test.want.DCVReuseDays {
				t.Errorf("DCVReuseAt(%s) = %d, want %d", test.instant, got, test.want.DCVReuseDays)
			}
		})
	}
}

func TestNextStepAfter(t *testing.T) {
	if effective, limits, ok := NextStepAfter(mustTime(t, "2017-06-01T00:00:00Z")); !ok ||
		!effective.Equal(time.Date(2018, 3, 1, 0, 0, 0, 0, time.UTC)) || limits.MaxValidityDays != 825 {
		t.Fatalf("2018 next step = %v %v %v", effective, limits, ok)
	}
	if effective, limits, ok := NextStepAfter(mustTime(t, "2019-06-01T00:00:00Z")); !ok ||
		!effective.Equal(time.Date(2020, 9, 1, 0, 0, 0, 0, time.UTC)) || limits.MaxValidityDays != 398 {
		t.Fatalf("2020 next step = %v %v %v", effective, limits, ok)
	}
	effective, limits, ok := NextStepAfter(mustTime(t, "2026-03-14T23:59:59Z"))
	if !ok || !effective.Equal(Effective200Days) || limits.MaxValidityDays != 200 {
		t.Fatalf("next step = %v %v %v", effective, limits, ok)
	}
	if _, _, ok := NextStepAfter(mustTime(t, "2030-01-01T00:00:00Z")); ok {
		t.Fatal("expected no next step after the last scheduled step")
	}
}

func TestAssessBoundaries(t *testing.T) {
	cases := []struct {
		name      string
		notBefore string
		days      int
		compliant bool
	}{
		{"before 2018 fits 1186", "2017-01-01T00:00:00Z", 1186, true},
		{"before 2018 exceeds 1186", "2017-01-01T00:00:00Z", 1187, false},
		{"last day before 2018 fits 1186", "2018-02-28T00:00:00Z", 1186, true},
		{"2018 step fits 825", "2018-03-01T00:00:00Z", 825, true},
		{"2018 step rejects 826", "2018-03-01T00:00:00Z", 826, false},
		{"last day before 2020 fits 825", "2020-08-31T00:00:00Z", 825, true},
		{"2020 step fits 398", "2020-09-01T00:00:00Z", 398, true},
		{"2020 step rejects 399", "2020-09-01T00:00:00Z", 399, false},
		{"pre-2026 fits 398", "2025-01-01T00:00:00Z", 398, true},
		{"pre-2026 exceeds 398", "2025-01-01T00:00:00Z", 399, false},
		{"last second before the 2026 step keeps 398", "2026-03-14T23:59:59Z", 398, true},
		{"first second of the 2026 step allows 200", "2026-03-15T00:00:00Z", 200, true},
		{"first second of the 2026 step rejects 201", "2026-03-15T00:00:00Z", 201, false},
		{"2027 step allows 100", "2027-03-15T00:00:00Z", 100, true},
		{"2027 step rejects 101", "2027-03-15T00:00:00Z", 101, false},
		{"2029 step allows 47", "2029-03-15T00:00:00Z", 47, true},
		{"2029 step rejects 48", "2029-03-15T00:00:00Z", 48, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			notBefore := mustTime(t, test.notBefore)
			assessment := Assess(notBefore, day(notBefore, test.days))
			if assessment.CompliantAtIssuance != test.compliant {
				t.Fatalf("compliant = %v, want %v (%+v)", assessment.CompliantAtIssuance, test.compliant, assessment)
			}
		})
	}
}

func TestAssessNextLimitAndEmptyDates(t *testing.T) {
	notBefore := mustTime(t, "2026-06-01T00:00:00Z")
	assessment := Assess(notBefore, day(notBefore, 150))
	if assessment.MaxValidityAtIssuanceDays != 200 {
		t.Errorf("max at issuance = %d, want 200", assessment.MaxValidityAtIssuanceDays)
	}
	if assessment.FitsNextLimit {
		t.Error("150 days must not fit the 100-day 2027 limit")
	}
	if assessment.NextLimitDays != 100 || assessment.NextLimitEffective != "2027-03-15T00:00:00Z" {
		t.Errorf("next limit = %d %q", assessment.NextLimitDays, assessment.NextLimitEffective)
	}

	if got := Assess(time.Time{}, time.Time{}); got != (Assessment{}) {
		t.Errorf("zero dates = %+v, want zero assessment", got)
	}
	future := mustTime(t, "2030-01-01T00:00:00Z")
	tail := Assess(future, day(future, 40))
	if tail.NextLimitEffective != "" || tail.FitsNextLimit != tail.CompliantAtIssuance {
		t.Errorf("post-schedule assessment = %+v", tail)
	}
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
