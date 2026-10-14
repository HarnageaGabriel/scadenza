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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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
	go func() {
		for {
			connection, acceptErr := blackhole.Accept()
			if acceptErr != nil {
				return
			}
			_ = connection
		}
	}()
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
