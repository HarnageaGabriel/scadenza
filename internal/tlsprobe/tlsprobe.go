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
	// ClassBlockedAddress means every resolved address of the host was
	// rejected by the special-address guard, so no address was dialed.
	ClassBlockedAddress ErrorClass = "blocked-address"
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
func (e *Error) Error() string {
	// The blocked-address class names the rejected address and the reason it
	// was rejected, so the operator can see which address stopped the probe.
	// Every other class keeps the short form.
	if e.Class == ClassBlockedAddress && e.Err != nil {
		return fmt.Sprintf("probe %s:%d: %s: %s", e.Host, e.Port, e.Class, e.Err)
	}
	return fmt.Sprintf("probe %s:%d: %s", e.Host, e.Port, e.Class)
}

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
//
// BlockSpecialAddresses guards against a host name that comes from untrusted
// Certificate Transparency data resolving to a special address such as
// loopback or the cloud metadata address 169.254.169.254. RFC 1918 private
// ranges, the shared address space and IPv6 unique local addresses are
// deliberately still probed: an internal estate is a legitimate scan target.
type Prober struct {
	Timeout  time.Duration
	Dialer   Dialer
	Resolver IPResolver
	Roots    *x509.CertPool
	Clock    clock.Clock
	// BlockSpecialAddresses rejects every resolved address that names a
	// special address before any dial happens: loopback, link-local unicast,
	// link-local multicast, interface-local multicast, multicast, the
	// unspecified address (0.0.0.0 and ::), and everything in 0.0.0.0/8,
	// including the IPv4-mapped and IPv4-compatible IPv6 forms of each.
	//
	// The IPv6 forms that carry an IPv4 address inside them are unwrapped
	// and the same rules are applied to the address they carry: the
	// IPv4-translated prefix (::ffff:0:0:0/96), the NAT64 well-known prefix
	// (64:ff9b::/96) and the 6to4 prefix (2002::/16). Two prefixes are
	// refused whole, because the address they carry cannot be found: the
	// local use NAT64 prefix (64:ff9b:1::/48) and Teredo (2001::/32).
	//
	// The well known cloud metadata endpoints are refused by exact address:
	// 100.100.100.200, 168.63.129.16, 192.0.0.192, 169.254.170.2 and
	// fd00:ec2::254.
	//
	// RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16),
	// the shared address space (100.64.0.0/10) and IPv6 unique local
	// addresses (fc00::/7) are not blocked, because an internal estate is a
	// legitimate scan target. The default is false, so a name the user typed
	// keeps its current behaviour.
	BlockSpecialAddresses bool
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
// the addresses that were dialed, and the classified error class.
//
// When BlockSpecialAddresses is set, every resolved address is checked before
// the first dial. An address that names a special address is never dialed,
// the remaining addresses are still probed, and a host whose addresses are all
// rejected fails with ClassBlockedAddress.
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
	dialAddresses := addresses
	if p.BlockSpecialAddresses {
		allowed, blocked := filterSpecialAddresses(addresses)
		if len(allowed) == 0 {
			return result, &Error{
				Class: ClassBlockedAddress,
				Host:  host,
				Port:  port,
				Err:   fmt.Errorf("address %s is %s", blocked.Address, blocked.Reason),
			}
		}
		dialAddresses = allowed
	}
	result.IPs = dialAddresses
	dialer := p.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: p.Timeout}
	}
	connection, err := dialResolved(ctx, dialer, dialAddresses, port)
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

// blockedAddress names a resolved address the probe refuses to dial and the
// reason it was rejected.
type blockedAddress struct {
	Address string
	Reason  string
}

// filterSpecialAddresses splits resolved addresses into the ones that may be
// dialed and the first address that was rejected, with the reason it was
// rejected. The order of the addresses is preserved, so the surviving
// addresses are dialed in the order they resolved.
func filterSpecialAddresses(addresses []string) ([]string, blockedAddress) {
	allowed := make([]string, 0, len(addresses))
	var blocked blockedAddress
	for _, address := range addresses {
		// A zone suffix (fe80::1%eth0) is not part of the address. An address
		// that still does not parse is refused: the guard fails closed.
		literal, _, _ := strings.Cut(address, "%")
		ip := net.ParseIP(literal)
		if ip == nil {
			if blocked.Address == "" {
				blocked = blockedAddress{Address: address, Reason: "an unparseable address"}
			}
			continue
		}
		reason := specialAddressReason(ip)
		if reason == "" {
			allowed = append(allowed, address)
			continue
		}
		if blocked.Address == "" {
			blocked = blockedAddress{Address: address, Reason: reason}
		}
	}
	return allowed, blocked
}

// specialAddressReason reports why an address is a special address the probe
// refuses to dial, or an empty string when the address may be dialed.
//
// The blocked set is loopback, link-local unicast, link-local multicast,
// interface-local multicast, multicast, the unspecified address (0.0.0.0 and
// ::), and every address in 0.0.0.0/8, together with the IPv4-mapped
// (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d) IPv6 forms of each.
//
// The IPv6 forms that carry an IPv4 address inside them are unwrapped and the
// same rules are applied to the address they carry: the IPv4-translated
// prefix (::ffff:0:0:0/96), the NAT64 well-known prefix (64:ff9b::/96), whose
// embedded address is in the last 32 bits, and the 6to4 prefix (2002::/16),
// whose embedded address is in bits 16 to 47. Two prefixes are refused whole,
// because the address they carry cannot be found: the local use NAT64 prefix
// (64:ff9b:1::/48), where the position of the embedded address depends on the
// prefix length, and the Teredo prefix (2001::/32), whose payload is
// obfuscated.
//
// The well known cloud metadata endpoints are refused by exact address:
// 100.100.100.200, 168.63.129.16, 192.0.0.192, 169.254.170.2 and
// fd00:ec2::254.
//
// RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), the
// shared address space (100.64.0.0/10) and IPv6 unique local addresses
// (fc00::/7) are deliberately not blocked: an internal estate is a legitimate
// scan target.
func specialAddressReason(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if reason := addressReason(ip); reason != "" {
		return reason
	}
	if reason := prefixReason(ip); reason != "" {
		return reason
	}
	if embedded := embeddedIPv4(ip); embedded != nil {
		return addressReason(embedded)
	}
	return ""
}

// addressReason classifies one address form.
func addressReason(ip net.IP) string {
	switch {
	case ip.IsUnspecified():
		return "an unspecified address"
	case ip.IsLoopback():
		return "a loopback address"
	case ip.IsLinkLocalUnicast():
		return "a link-local unicast address"
	case ip.IsLinkLocalMulticast():
		return "a link-local multicast address"
	case ip.IsInterfaceLocalMulticast():
		return "an interface-local multicast address"
	case ip.IsMulticast():
		return "a multicast address"
	}
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 0 {
		return "in the 0.0.0.0/8 range"
	}
	if isCloudMetadataAddress(ip) {
		return "a cloud metadata address"
	}
	return ""
}

// The prefixes the guard knows about, as the first bytes of the address on
// the wire. They are read-only.
var (
	// teredoPrefix is 2001::/32.
	teredoPrefix = []byte{0x20, 0x01, 0x00, 0x00}
	// localNAT64Prefix is 64:ff9b:1::/48.
	localNAT64Prefix = []byte{0x00, 0x64, 0xff, 0x9b, 0x00, 0x01}
	// nat64Prefix is 64:ff9b::/96.
	nat64Prefix = []byte{0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	// sixToFourPrefix is 2002::/16.
	sixToFourPrefix = []byte{0x20, 0x02}
	// ipv4TranslatedPrefix is ::ffff:0:0:0/96.
	ipv4TranslatedPrefix = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00}
)

// prefixReason refuses the IPv6 prefixes that carry an IPv4 address the guard
// cannot find: the local use NAT64 prefix and the Teredo prefix.
func prefixReason(ip net.IP) string {
	switch {
	case hasIPv6Prefix(ip, teredoPrefix):
		return "a Teredo tunnel address"
	case hasIPv6Prefix(ip, localNAT64Prefix):
		return "a local use NAT64 prefix"
	}
	return ""
}

// isCloudMetadataAddress reports whether an address is one of the well known
// cloud metadata endpoints. They are refused by exact address only: the
// shared address space (100.64.0.0/10) and the unique local addresses
// (fc00::/7) around them are used by internal estates and tailnets.
func isCloudMetadataAddress(ip net.IP) bool {
	switch ip.String() {
	case "100.100.100.200", // Alibaba Cloud.
		"168.63.129.16", // Azure platform address.
		"192.0.0.192",   // Oracle Cloud.
		"169.254.170.2", // Already refused as a link-local address.
		"fd00:ec2::254": // AWS IPv6.
		return true
	}
	return false
}

// embeddedIPv4 returns the IPv4 address carried inside an IPv6 address form
// that embeds one, and nil for every other address.
//
// The forms are the IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible
// (::a.b.c.d) addresses, the IPv4-translated addresses of the
// ::ffff:0:0:0/96 prefix (::ffff:0:a.b.c.d), whose embedded address is in the
// last 32 bits, the NAT64 addresses of the well-known prefix
// (64:ff9b::/96), whose embedded address is in the last 32 bits too, and the
// 6to4 addresses (2002::/16), whose embedded address is in bits 16 to 47.
func embeddedIPv4(ip net.IP) net.IP {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	if len(ip) != net.IPv6len {
		return nil
	}
	switch {
	case hasIPv6Prefix(ip, nat64Prefix):
		return ip[12:16]
	case hasIPv6Prefix(ip, sixToFourPrefix):
		return ip[2:6]
	case hasIPv6Prefix(ip, ipv4TranslatedPrefix):
		return ip[12:16]
	}
	// The IPv4-compatible form (::a.b.c.d): the first 96 bits are zero.
	for _, b := range ip[:12] {
		if b != 0 {
			return nil
		}
	}
	return ip[12:16]
}

// hasIPv6Prefix reports whether an IPv6 address starts with the given prefix
// bytes.
func hasIPv6Prefix(ip net.IP, prefix []byte) bool {
	if len(ip) != net.IPv6len || len(prefix) > len(ip) {
		return false
	}
	for index, value := range prefix {
		if ip[index] != value {
			return false
		}
	}
	return true
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
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) ||
		(errors.As(err, &netErr) && netErr.Timeout()) {
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
