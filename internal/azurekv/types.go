// Package azurekv reads Azure Key Vault certificates without reading secrets
// or keys. It exposes only list-certificate, get-policy, and get-certificate
// operations behind a consumer-side interface so tests never touch the network.
package azurekv

import (
	"context"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/clock"
	"github.com/HarnageaGabriel/scadenza/internal/owner"
)

const (
	// SourceName is the stable inventory and coverage source identifier.
	SourceName = "azure-keyvault"
)

// LifetimeAction is one Key Vault certificate lifetime action.
type LifetimeAction struct {
	Type               string `json:"type"`
	DaysBeforeExpiry   *int   `json:"days_before_expiry,omitempty"`
	LifetimePercentage *int   `json:"lifetime_percentage,omitempty"`
}

// Facts are the additive observation fields read for one certificate. They
// contain no certificate bytes and never contain private key material.
type Facts struct {
	Name                 string            `json:"name"`
	Vault                string            `json:"vault"`
	Version              string            `json:"version"`
	Enabled              *bool             `json:"enabled,omitempty"`
	NotBefore            time.Time         `json:"not_before"`
	NotAfter             time.Time         `json:"not_after"`
	Issuer               string            `json:"issuer"`
	PolicyValidityMonths *int              `json:"policy_validity_months,omitempty"`
	LifetimeActions      []LifetimeAction  `json:"lifetime_actions"`
	Tags                 map[string]string `json:"tags"`
	ContentType          string            `json:"content_type,omitempty"`
}

// Certificate is the correlated certificate facts read from Key Vault.
type Certificate struct {
	Fingerprint string
	Serial      string
	Names       []string
	NotBefore   time.Time
	NotAfter    time.Time
	Facts       Facts
	Owners      []owner.Owner
}

// CertificateProperty is one list result before certificate bytes are read.
type CertificateProperty struct {
	ID        string
	Enabled   *bool
	NotBefore time.Time
	NotAfter  time.Time
	Tags      map[string]string
}

// CertificatePage is one page of certificate properties.
type CertificatePage struct {
	Properties []CertificateProperty
	NextLink   string
}

// Policy is the subset of certificate policy needed for renewal evidence.
type Policy struct {
	Issuer          string
	ValidityMonths  *int
	LifetimeActions []LifetimeAction
	ContentType     string
}

// CertificateBundle is the public CER bytes and certificate attributes.
type CertificateBundle struct {
	CER         []byte
	Version     string
	Enabled     *bool
	NotBefore   time.Time
	NotAfter    time.Time
	Tags        map[string]string
	ContentType string
}

// API is the consumer-side read-only interface. Implementations must never
// expose get-secret or get-key operations.
type API interface {
	ListCertificateProperties(ctx context.Context, vaultURL, continuation string) (CertificatePage, error)
	GetCertificatePolicy(ctx context.Context, vaultURL, name, version string) (Policy, error)
	GetCertificate(ctx context.Context, vaultURL, name, version string) (CertificateBundle, error)
}

// LoadOptions configures one or more vault reads.
type LoadOptions struct {
	VaultURLs []string
	QPS       float64
	UserAgent string
	Owners    owner.Config
	// Clock times the request limiter. It defaults to the system wall clock.
	Clock clock.Clock
}

// ErrorKind classifies source failures without exposing raw error text.
type ErrorKind string

const (
	// ErrorUnauthorized means HTTP 401 and makes the source unavailable.
	ErrorUnauthorized ErrorKind = "unauthorized"
	// ErrorForbidden means HTTP 403 and makes the source partial.
	ErrorForbidden ErrorKind = "forbidden"
	// ErrorUnreachable means a transport or non-authentication HTTP failure.
	ErrorUnreachable ErrorKind = "unreachable"
	// ErrorInvalid means a vault URI or response was invalid.
	ErrorInvalid ErrorKind = "invalid"
	// ErrorCanceled means the caller's context ended.
	ErrorCanceled ErrorKind = "canceled"
)

// Problem is a safe structured failure. Raw SDK or HTTP error text is never
// returned to callers that render diagnostics.
type Problem struct {
	Kind       ErrorKind
	HTTPStatus int
	VaultHost  string
	// VaultUnavailable distinguishes a failed vault from a skipped item so
	// callers can report coverage without exposing additional diagnostics.
	VaultUnavailable bool
}

// Error is a safe source error.
type Error struct {
	Problem Problem
}

func (e *Error) Error() string {
	return string(e.Problem.Kind)
}

// Source is the read-only scan surface consumed by the CLI.
type Source interface {
	Scan(ctx context.Context) ([]Certificate, []Problem, error)
}
