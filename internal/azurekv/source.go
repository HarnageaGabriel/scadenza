package azurekv

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"iter"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/clock"
	"github.com/HarnageaGabriel/scadenza/internal/owner"
	"golang.org/x/sync/errgroup"
)

type scanner struct {
	api         API
	vaults      []string
	qps         float64
	concurrency int
	owners      owner.Config
	clock       clock.Clock
}

// vaultUserinfoMarker replaces the userinfo of a rejected vault URI.
const vaultUserinfoMarker = "redacted"

// ValidateVaultURL accepts only a clean HTTPS Key Vault URI. The value is
// used exactly as given and is never trimmed: a URI with leading or trailing
// whitespace is rejected instead of being silently corrected, because the
// same string is used for the request and for the reported vault host. No
// credential or secret value is accepted anywhere in the configuration
// surface.
func ValidateVaultURL(raw string) error {
	if strings.TrimSpace(raw) != raw {
		return invalidVaultURI(raw)
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return invalidVaultURI(raw)
	}
	return nil
}

// invalidVaultURI builds the rejection error for one vault URI.
func invalidVaultURI(raw string) error {
	return &VaultURIError{Value: sanitizeVaultURI(raw)}
}

// sanitizeVaultURI renders a rejected vault URI for a diagnostic. The value is
// quoted, so whitespace and control characters are visible and cannot forge a
// diagnostic line, and any userinfo is redacted, so a credential typed into
// the URI is never echoed.
func sanitizeVaultURI(raw string) string {
	return strconv.Quote(redactVaultUserinfo(raw))
}

// redactVaultUserinfo replaces the userinfo of a vault URI with a fixed
// marker. The authority ends at the first path, query, or fragment, and the
// userinfo is everything before the last "@" in it.
func redactVaultUserinfo(raw string) string {
	start := 0
	rest := raw
	if scheme := strings.Index(raw, "://"); scheme >= 0 {
		start = scheme + len("://")
		rest = raw[start:]
	}
	end := strings.IndexAny(rest, "/?#")
	authority, tail := rest, ""
	if end >= 0 {
		authority, tail = rest[:end], rest[end:]
	}
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return raw
	}
	return raw[:start] + vaultUserinfoMarker + authority[at:] + tail
}

// Load creates the production source using only the Azure default credential
// chain: environment variables, workload identity, managed identity, or az login.
func Load(options LoadOptions) (Source, error) {
	return NewSource(newSDKAPI(newDefaultCredential, options.UserAgent), options)
}

// NewSource assembles a bounded, rate-limited scanner around a consumer-side
// API implementation. Tests use fakes and never make network calls.
func NewSource(api API, options LoadOptions) (Source, error) {
	if api == nil {
		return nil, &Error{Problem: Problem{Kind: ErrorInvalid}}
	}
	vaults := make([]string, 0, len(options.VaultURLs))
	seen := map[string]bool{}
	for _, raw := range options.VaultURLs {
		if err := ValidateVaultURL(raw); err != nil {
			return nil, &Error{Problem: Problem{Kind: ErrorInvalid}}
		}
		vault := strings.TrimSuffix(raw, "/")
		if !seen[vault] {
			seen[vault] = true
			vaults = append(vaults, vault)
		}
	}
	if len(vaults) == 0 {
		return nil, &Error{Problem: Problem{Kind: ErrorInvalid}}
	}
	qps := options.QPS
	if qps <= 0 {
		qps = 5
	}
	clk := options.Clock
	if clk == nil {
		clk = clock.System{}
	}
	return &scanner{
		api:         api,
		vaults:      vaults,
		qps:         qps,
		concurrency: 4,
		owners:      options.Owners,
		clock:       clk,
	}, nil
}

// SetOwners is used by the CLI after loading the ownership configuration.
func (s *scanner) SetOwners(config owner.Config) { s.owners = config }

func (s *scanner) Scan(ctx context.Context) ([]Certificate, []Problem, error) {
	limiter := newRateLimiter(s.qps, s.clock)
	problems := []Problem{}
	certificates := []Certificate{}
	for _, vault := range s.vaults {
		vaultCertificates := []Certificate{}
		vaultFailed := false
		properties := []CertificateProperty{}
		for property, listErr := range s.listCertificateProperties(ctx, limiter, vault) {
			if listErr != nil {
				problem, cancelErr := scanProblem(listErr, vault)
				if cancelErr != nil {
					return nil, problems, cancelErr
				}
				problem.VaultUnavailable = true
				problems = append(problems, problem)
				vaultFailed = true
				break
			}
			properties = append(properties, property)
		}
		if vaultFailed {
			continue
		}
		for start := 0; start < len(properties); start += s.concurrency {
			if err := ctx.Err(); err != nil {
				return nil, problems, &Error{Problem: Problem{Kind: ErrorCanceled, VaultHost: vaultHost(vault)}}
			}
			end := min(start+s.concurrency, len(properties))
			var group errgroup.Group
			group.SetLimit(s.concurrency)
			results := make([]Certificate, end-start)
			itemProblems := make([]*Problem, end-start)
			for index := start; index < end; index++ {
				resultIndex := index - start
				property := properties[index]
				group.Go(func() error {
					certificate, itemErr := s.readCertificate(ctx, limiter, vault, property)
					if itemErr != nil {
						problem, _ := scanProblem(itemErr, vault)
						itemProblems[resultIndex] = &problem
						return nil
					}
					results[resultIndex] = certificate
					return nil
				})
			}
			_ = group.Wait()
			if err := ctx.Err(); err != nil {
				return nil, problems, &Error{Problem: Problem{Kind: ErrorCanceled, VaultHost: vaultHost(vault)}}
			}
			for _, problem := range itemProblems {
				if problem == nil {
					continue
				}
				if problem.Kind == ErrorUnauthorized {
					problem.VaultUnavailable = true
					vaultFailed = true
				}
				problems = append(problems, *problem)
			}
			if vaultFailed {
				break
			}
			for _, certificate := range results {
				if certificate.Fingerprint != "" {
					vaultCertificates = append(vaultCertificates, certificate)
				}
			}
		}
		if !vaultFailed {
			certificates = append(certificates, vaultCertificates...)
		}
	}
	sort.SliceStable(certificates, func(i, j int) bool {
		if certificates[i].Facts.Vault != certificates[j].Facts.Vault {
			return certificates[i].Facts.Vault < certificates[j].Facts.Vault
		}
		if certificates[i].Facts.Name != certificates[j].Facts.Name {
			return certificates[i].Facts.Name < certificates[j].Facts.Name
		}
		return certificates[i].Facts.Version < certificates[j].Facts.Version
	})
	return certificates, problems, nil
}

// listCertificateProperties streams SDK-style pages while applying the same
// request limiter used for certificate and policy reads.
func (s *scanner) listCertificateProperties(ctx context.Context, limiter *rateLimiter, vault string) iter.Seq2[CertificateProperty, error] {
	return func(yield func(CertificateProperty, error) bool) {
		continuation := ""
		seen := map[string]bool{}
		for {
			if err := limiter.Wait(ctx); err != nil {
				yield(CertificateProperty{}, err)
				return
			}
			page, err := s.api.ListCertificateProperties(ctx, vault, continuation)
			if err != nil {
				yield(CertificateProperty{}, err)
				return
			}
			for _, property := range page.Properties {
				if !yield(property, nil) {
					return
				}
			}
			if page.NextLink == "" || seen[page.NextLink] {
				return
			}
			seen[page.NextLink] = true
			continuation = page.NextLink
		}
	}
}

func (s *scanner) readCertificate(ctx context.Context, limiter *rateLimiter, vault string, property CertificateProperty) (Certificate, error) {
	name, version, ok := splitCertificateID(property.ID)
	if !ok {
		return Certificate{}, &Error{Problem: Problem{Kind: ErrorInvalid, VaultHost: vaultHost(vault)}}
	}
	if err := limiter.Wait(ctx); err != nil {
		return Certificate{}, &Error{Problem: Problem{Kind: ErrorCanceled, VaultHost: vaultHost(vault)}}
	}
	bundle, err := s.api.GetCertificate(ctx, vault, name, version)
	if err != nil {
		return Certificate{}, safeError(err, vault)
	}
	if err := limiter.Wait(ctx); err != nil {
		return Certificate{}, &Error{Problem: Problem{Kind: ErrorCanceled, VaultHost: vaultHost(vault)}}
	}
	policy, err := s.api.GetCertificatePolicy(ctx, vault, name, version)
	if err != nil {
		return Certificate{}, safeError(err, vault)
	}
	leaf, err := parseCertificate(bundle.CER)
	if err != nil {
		return Certificate{}, &Error{Problem: Problem{Kind: ErrorInvalid, VaultHost: vaultHost(vault)}}
	}
	enabled := bundle.Enabled
	if enabled == nil {
		enabled = property.Enabled
	}
	notBefore := bundle.NotBefore
	if notBefore.IsZero() {
		notBefore = property.NotBefore
	}
	notAfter := bundle.NotAfter
	if notAfter.IsZero() {
		notAfter = property.NotAfter
	}
	tags := cloneMap(bundle.Tags)
	if len(tags) == 0 {
		tags = cloneMap(property.Tags)
	}
	issuer := policy.Issuer
	if issuer == "" {
		issuer = "Unknown"
	}
	actions := append([]LifetimeAction(nil), policy.LifetimeActions...)
	if actions == nil {
		actions = []LifetimeAction{}
	}
	if tags == nil {
		tags = map[string]string{}
	}
	contentType := bundle.ContentType
	if contentType == "" {
		contentType = policy.ContentType
	}
	if bundle.Version != "" {
		version = bundle.Version
	}
	location := vaultHost(vault) + "/" + name + "@" + version
	facts := Facts{
		Name:                 name,
		Vault:                vaultHost(vault),
		Version:              version,
		Enabled:              enabled,
		NotBefore:            notBefore,
		NotAfter:             notAfter,
		Issuer:               issuer,
		PolicyValidityMonths: policy.ValidityMonths,
		LifetimeActions:      actions,
		Tags:                 tags,
		ContentType:          contentType,
	}
	dnsNames := names(leaf)
	owners := s.owners.Resolve(owner.Signals{
		Object: location,
		Labels: tags,
		Names:  dnsNames,
	})
	for index := range owners {
		if owners[index].Source == owner.SourceLabel {
			owners[index].Source = owner.Source("tag")
		}
	}
	return Certificate{
		Fingerprint: fingerprint(leaf.Raw),
		Serial:      serial(leaf),
		Names:       dnsNames,
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		Facts:       facts,
		Owners:      owners,
	}, nil
}

// ParseVaultHost returns only the host portion for safe diagnostics.
func ParseVaultHost(raw string) (string, error) {
	if err := ValidateVaultURL(raw); err != nil {
		return "", err
	}
	return vaultHost(raw), nil
}

func splitCertificateID(id string) (string, string, bool) {
	parsed, err := url.Parse(id)
	if err != nil {
		return "", "", false
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if (len(parts) != 2 && len(parts) != 3) || parts[0] != "certificates" {
		return "", "", false
	}
	name, version := parts[1], ""
	if len(parts) == 3 {
		version = parts[2]
	}
	return name, version, name != "" && (len(parts) == 2 || version != "")
}

func scanProblem(err error, vault string) (Problem, error) {
	safe := safeError(err, vault)
	var sourceErr *Error
	if errors.As(safe, &sourceErr) {
		if sourceErr.Problem.Kind == ErrorCanceled {
			return Problem{}, sourceErr
		}
		return sourceErr.Problem, nil
	}
	return Problem{Kind: ErrorUnreachable, VaultHost: vaultHost(vault)}, nil
}

func safeError(err error, vault string) error {
	host := vaultHost(vault)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return &Error{Problem: Problem{Kind: ErrorCanceled, VaultHost: host}}
	}
	var sourceErr *Error
	if errors.As(err, &sourceErr) {
		problem := sourceErr.Problem
		if problem.VaultHost == "" {
			problem.VaultHost = host
		}
		return &Error{Problem: problem}
	}
	return &Error{Problem: Problem{Kind: ErrorUnreachable, VaultHost: host}}
}

func vaultHost(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Host
}

func parseCertificate(data []byte) (*x509.Certificate, error) {
	der := data
	if block, _ := pem.Decode(data); block != nil {
		der = block.Bytes
	}
	return x509.ParseCertificate(der)
}

func fingerprint(der []byte) string {
	// SHA-256 is the inventory correlation key; x5t is SHA-1 and is not used.
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func serial(leaf *x509.Certificate) string {
	if leaf.SerialNumber == nil {
		return ""
	}
	return strings.ToLower(leaf.SerialNumber.Text(16))
}

func names(leaf *x509.Certificate) []string {
	values := append([]string(nil), leaf.DNSNames...)
	if len(values) == 0 && leaf.Subject.CommonName != "" {
		values = append(values, leaf.Subject.CommonName)
	}
	set := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || set[value] {
			continue
		}
		set[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func cloneMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

type rateLimiter struct {
	interval time.Duration
	clock    clock.Clock
	mu       sync.Mutex
	next     time.Time
}

func newRateLimiter(qps float64, clk clock.Clock) *rateLimiter {
	interval := time.Duration(float64(time.Second) / qps)
	return &rateLimiter{interval: interval, clock: clk}
}

func (l *rateLimiter) Wait(ctx context.Context) error {
	l.mu.Lock()
	now := l.clock.Now()
	wait := time.Duration(0)
	if l.next.After(now) {
		wait = l.next.Sub(now)
	}
	l.next = now.Add(wait + l.interval)
	l.mu.Unlock()
	if wait <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
