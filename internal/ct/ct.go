// Package ct searches and normalizes Certificate Transparency records.
package ct

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/policy"
	"golang.org/x/net/idna"
)

// Certificate is one normalized CT issuance.
type Certificate struct {
	Fingerprint  string    `json:"fingerprint_sha256"`
	Serial       string    `json:"serial"`
	SubjectNames []string  `json:"subject_names"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	LifetimeDays int       `json:"lifetime_days"`
	Verdict100D  string    `json:"verdict_100d"`
	// Policy is the dated validity assessment; verdict_100d stays unchanged.
	Policy   policy.Assessment `json:"policy"`
	Revoked  *bool             `json:"revoked"`
	Source   string            `json:"source"`
	DedupKey string            `json:"-"`
}

// Query describes a source lookup.
type Query struct {
	Domain            string
	IncludeSubdomains bool
	Limit             int
	Now               time.Time
	IncludeExpired    bool
}

// Source searches one CT backend.
type Source interface {
	Name() string
	Search(context.Context, Query) ([]Certificate, error)
}

// MaxEntries is the default cap on the entries received for one query. It
// applies when the caller leaves Query.Limit unset; a caller that sets a
// limit keeps it and the cap never shortens it.
const MaxEntries = 50000

// Result holds the entries collected for one query and reports whether the
// source stopped before it was exhausted.
type Result struct {
	Certificates []Certificate `json:"certificates"`
	Truncated    bool          `json:"truncated"`
}

// TruncatingSource is implemented by sources that report query truncation.
// A caller that needs to surface truncation type-asserts a Source to this
// interface and calls SearchResult.
type TruncatingSource interface {
	SearchResult(context.Context, Query) (Result, error)
}

// ErrorKind classifies recoverable source failures.
type ErrorKind string

const (
	// Unavailable means the source could not return a usable response.
	Unavailable ErrorKind = "unavailable"
	// RateLimited means the source refused the request due to quota.
	RateLimited ErrorKind = "rate_limited"
	// Malformed means the response could not be decoded safely.
	Malformed ErrorKind = "malformed"
)

// SourceError records a classified backend error without exposing secrets.
type SourceError struct {
	Kind   ErrorKind
	Source string
	Err    error
}

func (e *SourceError) Error() string { return fmt.Sprintf("%s: %s", e.Source, e.Kind) }
func (e *SourceError) Unwrap() error { return e.Err }

// Kind extracts a source error classification.
func Kind(err error) ErrorKind {
	var sourceErr *SourceError
	if errors.As(err, &sourceErr) {
		return sourceErr.Kind
	}
	return Unavailable
}

// NormalizeDomain validates and converts a DNS argument to lowercase ASCII.
func NormalizeDomain(value string) (string, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "*.")
	if value == "" || strings.ContainsAny(value, "/\\:@?#") || strings.Contains(value, "*") || net.ParseIP(value) != nil {
		return "", errors.New("not a DNS domain")
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil || len(ascii) > 253 {
		return "", errors.New("invalid IDNA domain")
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("invalid DNS label")
		}
	}
	if net.ParseIP(ascii) != nil {
		return "", errors.New("IP addresses are not domains")
	}
	return ascii, nil
}

// Finalize deduplicates, classifies, filters, limits, and sorts records.
func Finalize(certificates []Certificate, now time.Time, includeExpired bool, maximum int) ([]Certificate, bool) {
	seen := map[string]bool{}
	result := make([]Certificate, 0, len(certificates))
	for _, certificate := range certificates {
		certificate.SubjectNames = uniqueSorted(certificate.SubjectNames)
		certificate.LifetimeDays = int(certificate.NotAfter.Sub(certificate.NotBefore) / (24 * time.Hour))
		if certificate.NotAfter.Sub(certificate.NotBefore) <= 100*24*time.Hour {
			certificate.Verdict100D = "ok"
		} else {
			certificate.Verdict100D = "exceeds"
		}
		certificate.Policy = policy.Assess(certificate.NotBefore, certificate.NotAfter)
		key := certificate.Fingerprint
		if key == "" {
			key = certificate.DedupKey
		}
		if key == "" {
			key = fmt.Sprintf("%s|%s|%s", certificate.Issuer, certificate.Serial, certificate.NotBefore)
		}
		if seen[key] || (!includeExpired && certificate.NotAfter.Before(now)) {
			continue
		}
		seen[key] = true
		result = append(result, certificate)
	}
	sort.SliceStable(result, func(i, j int) bool { return less(result[i], result[j]) })
	truncated := maximum > 0 && len(result) > maximum
	if truncated {
		result = result[:maximum]
	}
	return result, truncated
}

// less is a total order: not_before descending, then fingerprint, dedup key, issuer, serial, names.
func less(a, b Certificate) bool {
	if !a.NotBefore.Equal(b.NotBefore) {
		return a.NotBefore.After(b.NotBefore)
	}
	left := [...]string{a.Fingerprint, a.DedupKey, a.Issuer, a.Serial, strings.Join(a.SubjectNames, "\n")}
	right := [...]string{b.Fingerprint, b.DedupKey, b.Issuer, b.Serial, strings.Join(b.SubjectNames, "\n")}
	for index := range left {
		if left[index] != right[index] {
			return left[index] < right[index]
		}
	}
	return false
}

func uniqueSorted(values []string) []string {
	set := map[string]bool{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			set[value] = true
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func endpoint(base string, parameters url.Values) string { return base + "?" + parameters.Encode() }
