package renewal

import (
	"sort"
)

// unownedOwner is the bucket for certificates with no declared owner. ADR 0006
// milestone M4b requires a deterministic summary, so unowned certificates are
// grouped rather than dropped.
const unownedOwner = "(unowned)"

// Owner is one auditable owner attribution, mirrored from internal/owner so
// that this package stays independent of the scan internals.
type Owner struct {
	Value  string
	Source string
}

// OwnerCertificate is one certificate's contribution to the per-owner summary.
type OwnerCertificate struct {
	Owners []Owner
	Mode   Mode
	Health Health
}

// ManualRenewals is the manual renewal workload per year at each upcoming CA/B
// maximum validity. It is the count of manual renewals an owner must perform in
// a year if their certificates are capped at 200, 100, or 47 days.
type ManualRenewals struct {
	Days200 int `json:"200d"`
	Days100 int `json:"100d"`
	Days47  int `json:"47d"`
}

// OwnerSummary is the renewal workload of one owner.
type OwnerSummary struct {
	Owner                 string         `json:"owner"`
	OwnerSource           string         `json:"owner_source"`
	Certificates          int            `json:"certificates"`
	Automatic             int            `json:"automatic"`
	Manual                int            `json:"manual"`
	Unknown               int            `json:"unknown"`
	Degraded              int            `json:"degraded"`
	ManualRenewalsPerYear ManualRenewals `json:"manual_renewals_per_year"`
}

// SummarizeOwners aggregates the per-owner renewal workload. Manual renewals per
// year are ceil(365 / max_validity) for every manual certificate: 2 at 200 days,
// 4 at 100 days, and 8 at 47 days.
func SummarizeOwners(certificates []OwnerCertificate) []OwnerSummary {
	type bucket struct {
		source        string
		certificates  int
		automatic     int
		manual        int
		unknown       int
		degraded      int
		manualRenewal ManualRenewals
	}
	buckets := map[string]*bucket{}
	for _, certificate := range certificates {
		owners := certificate.Owners
		if len(owners) == 0 {
			owners = []Owner{{Value: unownedOwner}}
		}
		seen := map[string]bool{}
		for _, entry := range owners {
			value := entry.Value
			if value == "" {
				value = unownedOwner
			}
			if seen[value] {
				continue
			}
			seen[value] = true
			current := buckets[value]
			if current == nil {
				current = &bucket{}
				buckets[value] = current
			}
			if entry.Source != "" && (current.source == "" || entry.Source < current.source) {
				current.source = entry.Source
			}
			current.certificates++
			switch certificate.Mode {
			case ModeAutomatic:
				current.automatic++
			case ModeManual:
				current.manual++
				current.manualRenewal.Days200 += renewalsPerYear(200)
				current.manualRenewal.Days100 += renewalsPerYear(100)
				current.manualRenewal.Days47 += renewalsPerYear(47)
			default:
				current.unknown++
			}
			if certificate.Health == HealthDegraded {
				current.degraded++
			}
		}
	}
	result := make([]OwnerSummary, 0, len(buckets))
	for owner, current := range buckets {
		result = append(result, OwnerSummary{
			Owner:                 owner,
			OwnerSource:           current.source,
			Certificates:          current.certificates,
			Automatic:             current.automatic,
			Manual:                current.manual,
			Unknown:               current.unknown,
			Degraded:              current.degraded,
			ManualRenewalsPerYear: current.manualRenewal,
		})
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].Owner < result[j].Owner })
	return result
}

// renewalsPerYear is ceil(365 / maxValidityDays): how many manual renewals a
// certificate with that lifetime needs in a year.
func renewalsPerYear(maxValidityDays int) int {
	if maxValidityDays <= 0 {
		return 0
	}
	return (365 + maxValidityDays - 1) / maxValidityDays
}
