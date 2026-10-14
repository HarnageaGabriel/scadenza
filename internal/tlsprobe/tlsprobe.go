// Package tlsprobe performs bounded live TLS handshakes to read the certificate
// chain a host presents. It never sends application data, closes the connection
// immediately after the handshake, and never trusts a probed server.
//
// The chain is read with verification disabled so that misconfigured, expired,
// or self-signed endpoints can still be inspected, and it is then re-verified
// against the system roots separately. See docs/adr/0004-tls-verification-policy.md
// for the rationale and for the scoped gosec exception in handshake.
package tlsprobe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/clock"
)

// ErrorClass classifies a failed probe without exposing peer data.
type ErrorClass string

const (
	// ClassDNS means the host name could not be resolved.
	ClassDNS ErrorClass = "dns"
	// ClassConnectTimeout means connecting or resolving exceeded the deadline.
	ClassConnectTimeout ErrorClass = "connect-timeout"
	// ClassRefused means the peer refused the connection.
	ClassRefused ErrorClass = "refused"
	// ClassCanceled means the caller canceled the probe.
	ClassCanceled ErrorClass = "canceled"
	// ClassTLSAlert means the peer sent a TLS alert or non-TLS data.
	ClassTLSAlert ErrorClass = "tls-alert"
	// ClassNoCertificate means the handshake completed without a leaf certificate.
	ClassNoCertificate ErrorClass = "no-certificate"
	// ClassHandshakeFailed means any other handshake failure.
	ClassHandshakeFailed ErrorClass = "handshake-failed"
)

// errNoCertificate reports a handshake that yielded no leaf certificate.
var errNoCertificate = errors.New("server presented no certificate")

// systemCertPool loads the platform root pool. It is a variable so the failure
// path can be exercised without corrupting the real system trust store.
var systemCertPool = x509.SystemCertPool

// Error is a classified probe failure.
type Error struct {
	Class ErrorClass
	Host  string
	Port  int
	Err   error
}

// Error implements error without printing peer-supplied data.
func (e *Error) Error() string { return fmt.Sprintf("probe %s:%d: %s", e.Host, e.Port, e.Class) }

// Unwrap returns the underlying cause.
func (e *Error) Unwrap() error { return e.Err }

// Dialer opens the TCP connection used for a handshake.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// IPResolver resolves a host name to its IP addresses. *net.Resolver
// implements it; tests inject a deterministic resolver.
type IPResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Result records what a single handshake observed.
type Result struct {
	Host                 string    `json:"host"`
	Port                 int       `json:"port"`
	SNI                  string    `json:"sni"`
	Fingerprint          string    `json:"fingerprint_sha256"`
	Serial               string    `json:"serial"`
	Names                []string  `json:"names"`
	Issuer               string    `json:"issuer"`
	NotBefore            time.Time `json:"not_before"`
	NotAfter             time.Time `json:"not_after"`
	TLSVersion           string    `json:"tls_version"`
	ChainHasIntermediate bool      `json:"chain_has_intermediate"`
	IPs                  []string  `json:"ips"`
	Trusted              bool      `json:"trusted"`
	VerifyError          string    `json:"verify_error"`
	ErrorClass           string    `json:"error_class"`
}

// Prober is a configurable TLS handshake issuer.
type Prober struct {
	Timeout  time.Duration
	Dialer   Dialer
	Resolver IPResolver
	Roots    *x509.CertPool
	Clock    clock.Clock
}

// New returns a prober with the default five second timeout.
func New() *Prober { return &Prober{Timeout: 5 * time.Second} }

// Probe performs one handshake with a default prober.
func Probe(ctx context.Context, host string, port int, sni string) (Result, error) {
	return New().Probe(ctx, host, port, sni)
}

// Probe performs one handshake and returns the presented leaf certificate.
// It resolves the host, dials, handshakes, and closes without sending any
// application bytes. On failure the returned Result carries the host, port,
// resolved addresses, and the classified error class.
func (p *Prober) Probe(ctx context.Context, host string, port int, sni string) (Result, error) {
	result := Result{Host: host, Port: port, SNI: sni}
	if result.SNI == "" && net.ParseIP(host) == nil {
		result.SNI = host
	}
	if port < 1 || port > 65535 {
		return result, &Error{Class: ClassHandshakeFailed, Host: host, Port: port, Err: errors.New("port out of range")}
	}
	if p.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.Timeout)
		defer cancel()
	}
	addresses, err := p.resolve(ctx, host)
	if err != nil {
		return result, &Error{Class: ClassDNS, Host: host, Port: port, Err: err}
	}
	if len(addresses) == 0 {
		return result, &Error{Class: ClassDNS, Host: host, Port: port, Err: errors.New("host resolved to no addresses")}
	}
	result.IPs = addresses
	dialer := p.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: p.Timeout}
	}
	connection, err := dialResolved(ctx, dialer, addresses, port)
	if err != nil {
		return result, &Error{Class: classifyDial(ctx, err), Host: host, Port: port, Err: err}
	}
	defer func() { _ = connection.Close() }()
	roots, rootsErr := p.roots()
	state, err := handshake(ctx, connection, &result, roots, rootsErr, p.now())
	if err != nil {
		return result, &Error{Class: classifyHandshake(ctx, err), Host: host, Port: port, Err: err}
	}
	result.TLSVersion = tlsVersionName(state.Version)
	return result, nil
}

// dialResolved connects to the first resolved address that accepts a
// connection, trying them in order and honouring ctx. It never resolves again,
// so the address dialed is one of the addresses already recorded.
func dialResolved(ctx context.Context, dialer Dialer, addresses []string, port int) (net.Conn, error) {
	var lastErr error
	for _, address := range addresses {
		connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(port)))
		if err == nil {
			return connection, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no address to dial")
	}
	return nil, lastErr
}

// handshake reads the peer chain. In-connection verification is disabled on
// purpose; capture re-verifies the chain against the system roots separately.
func handshake(ctx context.Context, connection net.Conn, result *Result, roots *x509.CertPool, rootsErr error, now time.Time) (tls.ConnectionState, error) {
	config := &tls.Config{ServerName: result.SNI}
	config.InsecureSkipVerify = true //nolint:gosec // G402: the chain must be read from expired, self-signed, or misconfigured servers; capture re-verifies it against the system roots. See docs/adr/0004-tls-verification-policy.md.
	//nolint:gosec // G123: this is a one-shot client handshake that never resumes a session and re-verifies the chain separately. See docs/adr/0004-tls-verification-policy.md.
	config.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		return capture(result, rawCerts, roots, rootsErr, now)
	}
	client := tls.Client(connection, config)
	if err := client.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, err
	}
	return client.ConnectionState(), nil
}

// capture records the leaf fingerprint and separately verifies the chain
// against the system roots. It returns an error only when no leaf is present.
func capture(result *Result, rawCerts [][]byte, roots *x509.CertPool, rootsErr error, now time.Time) error {
	if len(rawCerts) == 0 {
		return errNoCertificate
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parse leaf certificate: %w", err)
	}
	sum := sha256.Sum256(rawCerts[0])
	result.Fingerprint = hex.EncodeToString(sum[:])
	if leaf.SerialNumber != nil {
		result.Serial = strings.ToLower(leaf.SerialNumber.Text(16))
	}
	result.Names = subjectNames(leaf)
	result.Issuer = leaf.Issuer.String()
	result.NotBefore = leaf.NotBefore
	result.NotAfter = leaf.NotAfter
	result.ChainHasIntermediate = len(rawCerts) > 1
	if rootsErr != nil {
		result.Trusted = false
		result.VerifyError = "load system roots: " + rootsErr.Error()
		return nil
	}
	options := x509.VerifyOptions{Roots: roots, Intermediates: x509.NewCertPool(), CurrentTime: now}
	for _, der := range rawCerts[1:] {
		if parsed, parseErr := x509.ParseCertificate(der); parseErr == nil && options.Intermediates != nil {
			options.Intermediates.AddCert(parsed)
		}
	}
	// Trust must mean "valid for the probed name or IP": scope the verification
	// to the SNI when a name is known, and to the IP literal otherwise, where Go
	// matches it against the certificate's IP SANs. See ADR 0004.
	options.DNSName = result.SNI
	if options.DNSName == "" {
		options.DNSName = result.Host
	}
	if _, verifyErr := leaf.Verify(options); verifyErr != nil {
		result.Trusted = false
		result.VerifyError = verifyErr.Error()
	} else {
		result.Trusted = true
	}
	return nil
}

func subjectNames(leaf *x509.Certificate) []string {
	names := make([]string, 0, len(leaf.DNSNames)+1)
	names = append(names, leaf.DNSNames...)
	if len(leaf.DNSNames) == 0 && leaf.Subject.CommonName != "" {
		names = append(names, leaf.Subject.CommonName)
	}
	set := map[string]bool{}
	result := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" && !set[name] {
			set[name] = true
			result = append(result, name)
		}
	}
	sort.Strings(result)
	return result
}

func (p *Prober) resolve(ctx context.Context, host string) ([]string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}, nil
	}
	resolver := p.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addresses, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		value := address.IP.String()
		if !set[value] {
			set[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result, nil
}

func (p *Prober) roots() (*x509.CertPool, error) {
	if p.Roots != nil {
		return p.Roots, nil
	}
	pool, err := systemCertPool()
	if err != nil {
		return nil, err
	}
	return pool, nil
}

func (p *Prober) now() time.Time {
	if p.Clock != nil {
		return p.Clock.Now()
	}
	return clock.System{}.Now()
}

func classifyDial(ctx context.Context, err error) ErrorClass {
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return ClassCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ClassConnectTimeout
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ClassDNS
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ClassConnectTimeout
	}
	if errors.Is(err, refusedErrno) {
		return ClassRefused
	}
	return ClassHandshakeFailed
}

func classifyHandshake(ctx context.Context, err error) ErrorClass {
	if errors.Is(err, errNoCertificate) {
		return ClassNoCertificate
	}
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return ClassCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ClassConnectTimeout
	}
	if errors.Is(err, refusedErrno) {
		return ClassRefused
	}
	var alert tls.AlertError
	if errors.As(err, &alert) {
		return ClassTLSAlert
	}
	var record tls.RecordHeaderError
	if errors.As(err, &record) {
		return ClassTLSAlert
	}
	message := err.Error()
	if strings.Contains(message, "remote error: tls:") || strings.Contains(message, "does not look like a TLS handshake") {
		return ClassTLSAlert
	}
	return ClassHandshakeFailed
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}
