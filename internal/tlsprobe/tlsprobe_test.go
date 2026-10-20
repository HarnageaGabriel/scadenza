package tlsprobe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/clock"
)

// signedCertificate builds a certificate signed by parent. When parent is nil
// the certificate is self-signed. All material is generated in-process so the
// tests never touch the network or read any key from disk.
func signedCertificate(t *testing.T, template, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := template
	signingKey := key
	if parent != nil {
		signer = parent
		signingKey = parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// testNow fixes wall-clock time so certificate lifetimes and verification are deterministic.
var testNow = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

func authority(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(24 * 365 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certificate, key, _ := signedCertificate(t, template, nil, nil)
	return certificate, key
}

func leafTemplate(names []string, lifetime time.Duration) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(0xABCDEF),
		Subject:      pkix.Name{CommonName: firstOr(names, "leaf")},
		DNSNames:     names,
		NotBefore:    testNow.Add(-time.Minute),
		NotAfter:     testNow.Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

func firstOr(values []string, fallback string) string {
	if len(values) > 0 {
		return values[0]
	}
	return fallback
}

// serve starts an in-process TLS listener on the loopback interface and returns
// its host and port.
func serve(t *testing.T, config *tls.Config) (string, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, config)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, acceptErr := tlsListener.Accept()
			if acceptErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				if tlsConn, ok := conn.(*tls.Conn); ok {
					_ = tlsConn.Handshake()
				}
			}(connection)
		}
	}()
	t.Cleanup(func() {
		_ = tlsListener.Close()
		<-done
	})
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("unexpected listener address")
	}
	return "127.0.0.1", address.Port
}

func TestProbeReadsPresentedCertificate(t *testing.T) {
	ca, caKey := authority(t)
	_, _, leaf := signedCertificate(t, leafTemplate([]string{"www.example.test", "example.test"}, 90*24*time.Hour), ca, caKey)
	leaf.Certificate = append(leaf.Certificate, ca.Raw)
	host, port := serve(t, &tls.Config{Certificates: []tls.Certificate{leaf}})

	result, err := (&Prober{Clock: clock.Fixed{Time: testNow}, Timeout: 5 * time.Second}).Probe(context.Background(), host, port, "www.example.test")
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	if len(result.Fingerprint) != 64 {
		t.Fatalf("fingerprint = %q", result.Fingerprint)
	}
	if result.Serial != "abcdef" {
		t.Fatalf("serial = %q", result.Serial)
	}
	if strings.Join(result.Names, ",") != "example.test,www.example.test" {
		t.Fatalf("names = %v", result.Names)
	}
	if !result.ChainHasIntermediate {
		t.Fatal("expected an intermediate in the chain")
	}
	if result.TLSVersion == "" {
		t.Fatal("missing negotiated TLS version")
	}
	if result.Trusted || result.VerifyError == "" {
		t.Fatalf("untrusted chain reported trusted=%v verifyError=%q", result.Trusted, result.VerifyError)
	}
	if len(result.IPs) != 1 || result.IPs[0] != "127.0.0.1" {
		t.Fatalf("ips = %v", result.IPs)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	trusted, err := (&Prober{Clock: clock.Fixed{Time: testNow}, Timeout: 5 * time.Second, Roots: pool}).Probe(context.Background(), host, port, "www.example.test")
	if err != nil {
		t.Fatalf("trusted probe failed: %v", err)
	}
	if !trusted.Trusted || trusted.VerifyError != "" {
		t.Fatalf("expected trusted chain, got %v (%q)", trusted.Trusted, trusted.VerifyError)
	}
}

func TestProbeSNISelectsCertificate(t *testing.T) {
	_, _, first := signedCertificate(t, leafTemplate([]string{"first.test"}, 90*24*time.Hour), nil, nil)
	_, _, second := signedCertificate(t, leafTemplate([]string{"second.test"}, 90*24*time.Hour), nil, nil)
	host, port := serve(t, &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName == "second.test" {
			return &second, nil
		}
		return &first, nil
	}})

	prober := &Prober{Clock: clock.Fixed{Time: testNow}, Timeout: 5 * time.Second}
	result, err := prober.Probe(context.Background(), host, port, "second.test")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(result.Names, ",") != "second.test" {
		t.Fatalf("SNI second.test selected %v", result.Names)
	}
	other, err := prober.Probe(context.Background(), host, port, "first.test")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(other.Names, ",") != "first.test" {
		t.Fatalf("SNI first.test selected %v", other.Names)
	}
	if result.Fingerprint == other.Fingerprint {
		t.Fatal("expected distinct certificates for distinct SNI")
	}
}

func TestProbeExpiredAndLifetime(t *testing.T) {
	ca, caKey := authority(t)
	template := leafTemplate([]string{"expired.test"}, -time.Hour)
	_, _, leaf := signedCertificate(t, template, ca, caKey)
	leaf.Certificate = append(leaf.Certificate, ca.Raw)
	host, port := serve(t, &tls.Config{Certificates: []tls.Certificate{leaf}})

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	result, err := (&Prober{Clock: clock.Fixed{Time: testNow}, Timeout: 5 * time.Second, Roots: pool}).Probe(context.Background(), host, port, "expired.test")
	if err != nil {
		t.Fatalf("expired server should still be readable: %v", err)
	}
	if result.Trusted || !strings.Contains(result.VerifyError, "expired") {
		t.Fatalf("expired certificate reported trusted=%v verifyError=%q", result.Trusted, result.VerifyError)
	}

	longTemplate := leafTemplate([]string{"long.test"}, 101*24*time.Hour)
	_, _, longLeaf := signedCertificate(t, longTemplate, nil, nil)
	host, port = serve(t, &tls.Config{Certificates: []tls.Certificate{longLeaf}})
	long, err := (&Prober{Clock: clock.Fixed{Time: testNow}, Timeout: 5 * time.Second}).Probe(context.Background(), host, port, "long.test")
	if err != nil {
		t.Fatal(err)
	}
	days := int(long.NotAfter.Sub(long.NotBefore) / (24 * time.Hour))
	if days != 100 && days != 101 {
		t.Fatalf("recorded validity = %d days", days)
	}
}

func TestProbeSANLessFallsBackToCommonName(t *testing.T) {
	template := leafTemplate(nil, 90*24*time.Hour)
	template.Subject = pkix.Name{CommonName: "cn-only.test"}
	_, _, leaf := signedCertificate(t, template, nil, nil)
	host, port := serve(t, &tls.Config{Certificates: []tls.Certificate{leaf}})
	result, err := (&Prober{Clock: clock.Fixed{Time: testNow}, Timeout: 5 * time.Second}).Probe(context.Background(), host, port, "cn-only.test")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(result.Names, ",") != "cn-only.test" {
		t.Fatalf("names = %v", result.Names)
	}
}

func TestProbeErrorClasses(t *testing.T) {
	// Refused: bind a port, then close it so nothing listens.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().(*net.TCPAddr)
	_ = listener.Close()

	prober := &Prober{Clock: clock.Fixed{Time: testNow}, Timeout: 2 * time.Second}
	_, err = prober.Probe(context.Background(), "127.0.0.1", address.Port, "")
	if class(err) != ClassRefused {
		t.Fatalf("refused probe class = %v (err=%v)", class(err), err)
	}

	// TLS alert: a plain HTTP server does not speak TLS.
	plain := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("not tls"))
	}))
	defer plain.Close()
	plainAddress := strings.TrimPrefix(plain.URL, "http://")
	hostName, portText, splitErr := net.SplitHostPort(plainAddress)
	if splitErr != nil {
		t.Fatal(splitErr)
	}
	port := mustAtoi(t, portText)
	_, err = prober.Probe(context.Background(), hostName, port, "plain.test")
	if class(err) != ClassTLSAlert {
		t.Fatalf("plain HTTP probe class = %v (err=%v)", class(err), err)
	}

	// DNS: a resolver that always fails.
	failing := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("no resolver configured")
	}}
	_, err = (&Prober{Clock: clock.Fixed{Time: testNow}, Dialer: &net.Dialer{}, Resolver: failing}).Probe(context.Background(), "unresolvable.test", 443, "")
	if class(err) != ClassDNS {
		t.Fatalf("dns probe class = %v (err=%v)", class(err), err)
	}

	// Connect timeout: a socket that never answers.
	blackhole, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blackhole.Close() }()
	// With nothing referencing an accepted connection the GC can finalize it and
	// close the socket, turning a read into EOF. Keeping the conns alive until
	// the test ends makes the probe reliably hit the connect timeout.
	var held sync.Mutex
	var heldConnections []net.Conn
	go func() {
		for {
			connection, acceptErr := blackhole.Accept()
			if acceptErr != nil {
				return
			}
			held.Lock()
			heldConnections = append(heldConnections, connection)
			held.Unlock()
		}
	}()
	t.Cleanup(func() {
		held.Lock()
		defer held.Unlock()
		for _, connection := range heldConnections {
			_ = connection.Close()
		}
		heldConnections = nil
	})
	blackholeAddress := blackhole.Addr().(*net.TCPAddr)
	_, err = (&Prober{Clock: clock.Fixed{Time: testNow}, Timeout: 150 * time.Millisecond}).Probe(context.Background(), "127.0.0.1", blackholeAddress.Port, "")
	if class(err) != ClassConnectTimeout {
		t.Fatalf("timeout probe class = %v (err=%v)", class(err), err)
	}
}

func class(err error) ErrorClass {
	var probeErr *Error
	if errors.As(err, &probeErr) {
		return probeErr.Class
	}
	return ""
}

func mustAtoi(t *testing.T, value string) int {
	t.Helper()
	parsed := 0
	for _, r := range value {
		parsed = parsed*10 + int(r-'0')
	}
	return parsed
}

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		defaultPort int
		wantHost    string
		wantPort    int
		invalid     bool
	}{
		{name: "host default", input: "example.com", defaultPort: 443, wantHost: "example.com", wantPort: 443},
		{name: "host port", input: "Example.COM:8443", defaultPort: 443, wantHost: "example.com", wantPort: 8443},
		{name: "spaces", input: "  example.com  ", defaultPort: 443, wantHost: "example.com", wantPort: 443},
		{name: "ipv4 port", input: "192.0.2.10:8443", defaultPort: 443, wantHost: "192.0.2.10", wantPort: 8443},
		{name: "ipv6 no port", input: "::1", defaultPort: 443, wantHost: "::1", wantPort: 443},
		{name: "ipv6 bracket port", input: "[::1]:8443", defaultPort: 443, wantHost: "::1", wantPort: 8443},
		{name: "ipv6 bracket", input: "[::1]", defaultPort: 443, wantHost: "::1", wantPort: 443},
		{name: "trailing dot", input: "Example.com.", defaultPort: 443, wantHost: "example.com", wantPort: 443},
		{name: "trailing dot port", input: "www.example.com.:8443", defaultPort: 443, wantHost: "www.example.com", wantPort: 8443},
		{name: "control character", input: "exa\x01mple.com", defaultPort: 443, invalid: true},
		{name: "newline", input: "example.com\n.evil", defaultPort: 443, invalid: true},
		{name: "scheme", input: "https://example.com", defaultPort: 443, invalid: true},
		{name: "path", input: "example.com/path", defaultPort: 443, invalid: true},
		{name: "wildcard", input: "*.example.com", defaultPort: 443, invalid: true},
		{name: "empty", input: "   ", defaultPort: 443, invalid: true},
		{name: "empty host", input: ":443", defaultPort: 443, invalid: true},
		{name: "bad port", input: "example.com:https", defaultPort: 443, invalid: true},
		{name: "port range", input: "example.com:70000", defaultPort: 443, invalid: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			host, port, err := ParseEndpoint(test.input, test.defaultPort)
			if (err != nil) != test.invalid {
				t.Fatalf("ParseEndpoint(%q) error = %v", test.input, err)
			}
			if test.invalid {
				return
			}
			if host != test.wantHost || port != test.wantPort {
				t.Fatalf("ParseEndpoint(%q) = %q, %d; want %q, %d", test.input, host, port, test.wantHost, test.wantPort)
			}
		})
	}
}

func FuzzParseEndpoint(f *testing.F) {
	for _, seed := range []string{"example.com", "Example.COM:8443", "[::1]:443", "::1", "*.example.com", "https://x/y", "", ":", "example.com:70000"} {
		f.Add(seed, 443)
	}
	f.Fuzz(func(t *testing.T, value string, defaultPort int) {
		host, port, err := ParseEndpoint(value, defaultPort)
		if err != nil {
			return
		}
		if host == "" {
			t.Fatalf("accepted empty host for %q", value)
		}
		if port < 1 || port > 65535 {
			t.Fatalf("accepted out-of-range port %d for %q", port, value)
		}
		if strings.ContainsAny(host, " \t\n/*") {
			t.Fatalf("accepted invalid host %q", host)
		}
	})
}

func TestTLSVersionName(t *testing.T) {
	cases := map[uint16]string{tls.VersionTLS13: "TLS1.3", tls.VersionTLS12: "TLS1.2", 0x0300: "0x0300"}
	for version, want := range cases {
		if got := tlsVersionName(version); got != want {
			t.Fatalf("tlsVersionName(%#x) = %q, want %q", version, got, want)
		}
	}
}

// countingResolver records how many times it resolves a name so a test can prove
// the probe dials the addresses it already resolved instead of resolving again.
type countingResolver struct {
	mu    sync.Mutex
	calls int
	ip    net.IP
}

func (r *countingResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	return []net.IPAddr{{IP: r.ip}}, nil
}

func (r *countingResolver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// TestProbeDialsResolvedAddresses proves the probe connects to the address the
// injected resolver returned, records that address as Result.IPs, and does not
// resolve the name a second time. "resolved.test" has no DNS entry, so a second
// lookup would fail the handshake.
func TestProbeDialsResolvedAddresses(t *testing.T) {
	_, _, leaf := signedCertificate(t, leafTemplate([]string{"resolved.test"}, 90*24*time.Hour), nil, nil)
	host, port := serve(t, &tls.Config{Certificates: []tls.Certificate{leaf}})
	resolver := &countingResolver{ip: net.ParseIP(host)}
	prober := &Prober{Clock: clock.Fixed{Time: testNow}, Timeout: 5 * time.Second, Resolver: resolver}
	result, err := prober.Probe(context.Background(), "resolved.test", port, "resolved.test")
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	if len(result.IPs) != 1 || result.IPs[0] != "127.0.0.1" {
		t.Fatalf("result.IPs = %v, want the dialed address", result.IPs)
	}
	if resolver.count() != 1 {
		t.Fatalf("resolver called %d times, want exactly one resolution", resolver.count())
	}
}

// TestProbeIPLiteralChecksIPName proves that an IP-literal probe with no SNI is
// verified against the IP, so a chain for an unrelated public name is not
// reported trusted while a certificate carrying the IP SAN is.
func TestProbeIPLiteralChecksIPName(t *testing.T) {
	ca, caKey := authority(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	prober := &Prober{Clock: clock.Fixed{Time: testNow}, Timeout: 5 * time.Second, Roots: pool}

	_, _, unrelated := signedCertificate(t, leafTemplate([]string{"unrelated.example.test"}, 90*24*time.Hour), ca, caKey)
	unrelated.Certificate = append(unrelated.Certificate, ca.Raw)
	unrelatedHost, unrelatedPort := serve(t, &tls.Config{Certificates: []tls.Certificate{unrelated}})
	result, err := prober.Probe(context.Background(), unrelatedHost, unrelatedPort, "")
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	if result.Trusted {
		t.Fatalf("chain for unrelated.example.test reported trusted for IP literal %s (verifyError=%q)", unrelatedHost, result.VerifyError)
	}

	ipTemplate := leafTemplate(nil, 90*24*time.Hour)
	ipTemplate.IPAddresses = []net.IP{net.ParseIP(unrelatedHost)}
	_, _, ipLeaf := signedCertificate(t, ipTemplate, ca, caKey)
	ipLeaf.Certificate = append(ipLeaf.Certificate, ca.Raw)
	ipHost, ipPort := serve(t, &tls.Config{Certificates: []tls.Certificate{ipLeaf}})
	trusted, err := prober.Probe(context.Background(), ipHost, ipPort, "")
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	if !trusted.Trusted {
		t.Fatalf("certificate carrying the IP SAN reported untrusted: %q", trusted.VerifyError)
	}
}

// TestClassifyErrorsArePortable proves refused connections are matched through
// the wrapped errno (not a substring of the message) and that cancellation has
// its own class.
func TestClassifyErrorsArePortable(t *testing.T) {
	if got := classifyDial(context.Background(), errors.New("dial tcp: connection refused")); got != ClassHandshakeFailed {
		t.Fatalf("message-only refused text classified as %v; the class must not come from the message", got)
	}
	if got := classifyDial(context.Background(), fmt.Errorf("dial tcp 127.0.0.1:1: %w", refusedErrno)); got != ClassRefused {
		t.Fatalf("wrapped refused errno classified as %v", got)
	}
	if got := classifyHandshake(context.Background(), fmt.Errorf("write: %w", refusedErrno)); got != ClassRefused {
		t.Fatalf("handshake refused errno classified as %v", got)
	}
	if got := classifyDial(context.Background(), context.Canceled); got != ClassCanceled {
		t.Fatalf("canceled dial classified as %v", got)
	}
	if got := classifyHandshake(context.Background(), context.Canceled); got != ClassCanceled {
		t.Fatalf("canceled handshake classified as %v", got)
	}
}

// TestProbeSystemRootsErrorSurfaced proves a SystemCertPool failure is reported
// in verify_error instead of silently trusting nothing (or everything).
func TestProbeSystemRootsErrorSurfaced(t *testing.T) {
	original := systemCertPool
	systemCertPool = func() (*x509.CertPool, error) { return nil, errors.New("root store unavailable") }
	t.Cleanup(func() { systemCertPool = original })

	_, _, leaf := signedCertificate(t, leafTemplate([]string{"roots.test"}, 90*24*time.Hour), nil, nil)
	host, port := serve(t, &tls.Config{Certificates: []tls.Certificate{leaf}})
	result, err := (&Prober{Clock: clock.Fixed{Time: testNow}, Timeout: 5 * time.Second}).Probe(context.Background(), host, port, "roots.test")
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	if result.Trusted || !strings.Contains(result.VerifyError, "root store unavailable") {
		t.Fatalf("roots error not surfaced: trusted=%v verifyError=%q", result.Trusted, result.VerifyError)
	}
}

// stubResolver answers every name with the same fixed set of addresses, so a
// test can decide what a host name resolves to.
type stubResolver struct {
	mu        sync.Mutex
	calls     int
	addresses []string
}

func (r *stubResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	result := make([]net.IPAddr, 0, len(r.addresses))
	for _, address := range r.addresses {
		result = append(result, net.IPAddr{IP: net.ParseIP(address)})
	}
	return result, nil
}

func (r *stubResolver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// recordingDialer records every address the probe asks it to dial. When
// target is set it connects there instead, so a test can complete a handshake
// for an address no test server listens on.
type recordingDialer struct {
	mu     sync.Mutex
	dialed []string
	target string
}

func (d *recordingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, address)
	d.mu.Unlock()
	if d.target == "" {
		return nil, errors.New("test dialer refuses to connect")
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, d.target)
}

func (d *recordingDialer) dialedAddresses() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dialed...)
}

// TestSpecialAddressReasonBlocksSpecialAddresses proves the guard rejects
// every special address, including the IPv4-mapped and IPv4-compatible IPv6
// forms, and keeps the private ranges an internal estate needs.
func TestSpecialAddressReasonBlocksSpecialAddresses(t *testing.T) {
	blocked := []string{
		"127.0.0.1",
		"127.1.2.3",
		"::1",
		"169.254.169.254",
		"::ffff:169.254.169.254",
		"::ffff:127.0.0.1",
		"fe80::1",
		"0.0.0.0",
		"::",
		"224.0.0.1",
		"ff02::1",
		"0.1.2.3",
	}
	for _, address := range blocked {
		ip := net.ParseIP(address)
		if ip == nil {
			t.Fatalf("test address %q does not parse", address)
		}
		if specialAddressReason(ip) == "" {
			t.Fatalf("address %q was not blocked", address)
		}
	}

	allowed := []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "fd00::1", "8.8.8.8"}
	for _, address := range allowed {
		ip := net.ParseIP(address)
		if ip == nil {
			t.Fatalf("test address %q does not parse", address)
		}
		if reason := specialAddressReason(ip); reason != "" {
			t.Fatalf("address %q was blocked as %q", address, reason)
		}
	}
}

// TestFilterSpecialAddressesKeepsAllowedAddresses proves the filter drops only
// the special addresses, keeps the order of the rest, and reports the first
// rejected address with its reason.
func TestFilterSpecialAddressesKeepsAllowedAddresses(t *testing.T) {
	allowed, blocked := filterSpecialAddresses([]string{"10.0.0.1", "127.0.0.1", "8.8.8.8", "169.254.169.254"})
	if strings.Join(allowed, ",") != "10.0.0.1,8.8.8.8" {
		t.Fatalf("allowed = %v", allowed)
	}
	if blocked.Address != "127.0.0.1" {
		t.Fatalf("blocked address = %q, want the first rejected address", blocked.Address)
	}
	if blocked.Reason != "a loopback address" {
		t.Fatalf("blocked reason = %q", blocked.Reason)
	}
}

// TestProbeBlocksSpecialAddresses proves a host that resolves only to special
// addresses is never dialed and fails with its own class. The error names the
// host and the reason, and never a resolver answer beyond the rejected
// address itself.
func TestProbeBlocksSpecialAddresses(t *testing.T) {
	dialer := &recordingDialer{}
	resolver := &stubResolver{addresses: []string{"127.0.0.1", "169.254.169.254"}}
	prober := &Prober{
		Clock:                 clock.Fixed{Time: testNow},
		Timeout:               2 * time.Second,
		Resolver:              resolver,
		Dialer:                dialer,
		BlockSpecialAddresses: true,
	}
	result, err := prober.Probe(context.Background(), "metadata.example.test", 443, "")
	if class(err) != ClassBlockedAddress {
		t.Fatalf("blocked probe class = %v (err=%v)", class(err), err)
	}
	if len(dialer.dialedAddresses()) != 0 {
		t.Fatalf("probe dialed %v", dialer.dialedAddresses())
	}
	if len(result.IPs) != 0 {
		t.Fatalf("result.IPs = %v, want no dialed address", result.IPs)
	}
	text := err.Error()
	if !strings.Contains(text, "metadata.example.test") {
		t.Fatalf("error text %q does not name the host", text)
	}
	if !strings.Contains(text, "loopback") {
		t.Fatalf("error text %q does not name the reason", text)
	}
	if strings.Contains(text, "169.254.169.254") {
		t.Fatalf("error text %q leaked another resolver answer", text)
	}
}

// TestProbeBlocksSpecialAddressIPLiteral proves an IP literal host is checked
// the same way as a resolved name, and that the cloud metadata address is
// never dialed.
func TestProbeBlocksSpecialAddressIPLiteral(t *testing.T) {
	dialer := &recordingDialer{}
	prober := &Prober{
		Clock:                 clock.Fixed{Time: testNow},
		Timeout:               2 * time.Second,
		Dialer:                dialer,
		BlockSpecialAddresses: true,
	}
	_, err := prober.Probe(context.Background(), "169.254.169.254", 80, "")
	if class(err) != ClassBlockedAddress {
		t.Fatalf("blocked literal class = %v (err=%v)", class(err), err)
	}
	if len(dialer.dialedAddresses()) != 0 {
		t.Fatalf("probe dialed %v", dialer.dialedAddresses())
	}
	if !strings.Contains(err.Error(), "link-local") {
		t.Fatalf("error text %q does not name the reason", err.Error())
	}
}

// TestProbeProbesAllowedAddressWhenAnotherIsBlocked proves a host that
// resolves to one blocked and one allowed address still probes the allowed
// address, that the blocked address is never dialed, and that the probe dials
// the address it resolved instead of resolving the name again.
func TestProbeProbesAllowedAddressWhenAnotherIsBlocked(t *testing.T) {
	_, _, leaf := signedCertificate(t, leafTemplate([]string{"mixed.example.test"}, 90*24*time.Hour), nil, nil)
	host, port := serve(t, &tls.Config{Certificates: []tls.Certificate{leaf}})
	dialer := &recordingDialer{target: fmt.Sprintf("%s:%d", host, port)}
	resolver := &stubResolver{addresses: []string{"127.0.0.1", "203.0.113.10"}}
	prober := &Prober{
		Clock:                 clock.Fixed{Time: testNow},
		Timeout:               5 * time.Second,
		Resolver:              resolver,
		Dialer:                dialer,
		BlockSpecialAddresses: true,
	}
	result, err := prober.Probe(context.Background(), "mixed.example.test", port, "mixed.example.test")
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	if len(result.IPs) != 1 || result.IPs[0] != "203.0.113.10" {
		t.Fatalf("result.IPs = %v, want the allowed address", result.IPs)
	}
	dialed := dialer.dialedAddresses()
	if len(dialed) != 1 || dialed[0] != fmt.Sprintf("203.0.113.10:%d", port) {
		t.Fatalf("dialed = %v, want only the allowed address", dialed)
	}
	if resolver.count() != 1 {
		t.Fatalf("resolver called %d times, want exactly one resolution", resolver.count())
	}
}

// TestProbeWithoutGuardBlocksNothing proves the guard is off by default: a
// name that resolves to a special address is still dialed and the blocked
// class never appears.
func TestProbeWithoutGuardBlocksNothing(t *testing.T) {
	_, _, leaf := signedCertificate(t, leafTemplate([]string{"open.example.test"}, 90*24*time.Hour), nil, nil)
	host, port := serve(t, &tls.Config{Certificates: []tls.Certificate{leaf}})
	dialer := &recordingDialer{target: fmt.Sprintf("%s:%d", host, port)}
	prober := &Prober{
		Clock:    clock.Fixed{Time: testNow},
		Timeout:  5 * time.Second,
		Resolver: &stubResolver{addresses: []string{"127.0.0.1", "169.254.169.254"}},
		Dialer:   dialer,
	}
	result, err := prober.Probe(context.Background(), "open.example.test", port, "open.example.test")
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	if len(result.IPs) != 2 {
		t.Fatalf("result.IPs = %v, want every resolved address", result.IPs)
	}
	dialed := dialer.dialedAddresses()
	if len(dialed) != 1 || dialed[0] != fmt.Sprintf("127.0.0.1:%d", port) {
		t.Fatalf("dialed = %v, want the first resolved address", dialed)
	}
}

func TestFilterSpecialAddressesFailsClosed(t *testing.T) {
	allowed, blocked := filterSpecialAddresses([]string{"not-an-ip", "fe80::1%eth0", "10.0.0.1"})
	if len(allowed) != 1 || allowed[0] != "10.0.0.1" {
		t.Fatalf("allowed = %v, want only the private address", allowed)
	}
	if blocked.Address != "not-an-ip" || blocked.Reason == "" {
		t.Fatalf("blocked = %+v, want the unparseable address first", blocked)
	}
	allowed, blocked = filterSpecialAddresses([]string{"fe80::1%eth0"})
	if len(allowed) != 0 || blocked.Address != "fe80::1%eth0" {
		t.Fatalf("zoned link-local address was allowed: allowed=%v blocked=%+v", allowed, blocked)
	}
}
