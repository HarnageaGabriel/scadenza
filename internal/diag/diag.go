// Package diag defines stable diagnostics and their embedded registry.
package diag

// Severity is a diagnostic impact level.
type Severity string

const (
	// SeverityError prevents the requested operation from completing.
	SeverityError Severity = "error"
	// SeverityWarning records a condition that needs attention.
	SeverityWarning Severity = "warning"
	// SeverityInfo records a non-failing informational condition.
	SeverityInfo Severity = "info"
)

// Diagnostic is one reported problem.
type Diagnostic struct {
	Code        string   `json:"code"`
	Slug        string   `json:"slug"`
	Severity    Severity `json:"severity"`
	Summary     string   `json:"summary"`
	Explanation string   `json:"explanation"`
	Remediation string   `json:"remediation"`
}
