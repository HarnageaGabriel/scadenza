package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/clock"
	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/httpx"
	"github.com/HarnageaGabriel/scadenza/internal/inventory"
	"github.com/HarnageaGabriel/scadenza/internal/tlsprobe"
)

var updateGolden = flag.Bool("update", false, "update golden files")

// fakeProber returns scripted results without touching the network.
type fakeProber struct {
	results  map[string]tlsprobe.Result
	failures map[string]tlsprobe.ErrorClass
}

func (f fakeProber) Probe(_ context.Context, host string, port int, _ string) (tlsprobe.Result, error) {
	key := host + ":" + strconv.Itoa(port)
	if class, ok := f.failures[key]; ok {
		return tlsprobe.Result{Host: host, Port: port, ErrorClass: string(class)}, &tlsprobe.Error{Class: class, Host: host, Port: port, Err: errors.New("scripted failure")}
	}
	result, ok := f.results[key]
	if !ok {
		return tlsprobe.Result{Host: host, Port: port}, &tlsprobe.Error{Class: tlsprobe.ClassHandshakeFailed, Host: host, Port: port, Err: errors.New("no scripted result")}
	}
	result.Host, result.Port = host, port
	return result, nil
}

func scanCTFixture() string {
	return fmt.Sprintf(`[
{"id":"1","cert_sha256":"%s","dns_names":["example.com","www.example.com"],"issuer":{"friendly_name":"Example CA","name":"CN=Example Root"},"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","revoked":false},
{"id":"2","cert_sha256":"%s","dns_names":["api.example.com"],"issuer":{"name":"CN=Example Root"},"not_before":"2026-01-01T00:00:00Z","not_after":"2026-07-20T00:00:00Z","revoked":false},
{"id":"3","cert_sha256":"%s","dns_names":["*.example.com"],"issuer":{"name":"CN=Example Root"},"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","revoked":false}
]`, strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64))
}

func certSpotterServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.URL.Query().Get("after") != "" {
			_, _ = writer.Write([]byte("[]"))
			return
		}
		_, _ = writer.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

func scanDependencies(certURL string, prober hostProber) ctDependencies {
	client := &httpx.Client{HTTP: http.DefaultClient, UserAgent: "test", MaxAttempts: 1, Sleep: func(context.Context, time.Duration) error { return nil }}
	return ctDependencies{
		clock:   clock.Fixed{Time: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)},
		sources: map[string]ct.Source{"certspotter": &ct.CertSpotter{Client: client, URL: certURL}, "crtsh": &ct.CrtSH{Client: client, URL: certURL}},
		prober:  prober,
	}
}

func goldenProber() fakeProber {
	return fakeProber{
		results: map[string]tlsprobe.Result{
			"www.example.com:443": {Fingerprint: strings.Repeat("a", 64), Serial: "0a", Names: []string{"www.example.com"}, Issuer: "CN=Example Live Root", NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), Trusted: true, TLSVersion: "TLS1.3", IPs: []string{"192.0.2.1"}},
			"example.com:443":     {Fingerprint: strings.Repeat("d", 64), Serial: "0d", Names: []string{"example.com"}, Issuer: "CN=Self Signed", NotBefore: time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), Trusted: false, TLSVersion: "TLS1.2", VerifyError: "x509: certificate signed by unknown authority"},
		},
		failures: map[string]tlsprobe.ErrorClass{"api.example.com:443": tlsprobe.ClassRefused},
	}
}

func TestScanGoldenFormats(t *testing.T) {
	server := certSpotterServer(t, scanCTFixture())
	for _, format := range []string{"table", "json", "csv"} {
		t.Run(format, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := execute([]string{"scan", "--domain", "example.com", "--source", "certspotter", "--format", format}, &stdout, &stderr, scanDependencies(server.URL, goldenProber()))
			if code != ExitFindingsPresent {
				t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
			}
			path := filepath.Join("..", "..", "testdata", "golden", "scan."+format+".golden")
			if *updateGolden {
				if err := os.WriteFile(path, []byte(normalizeLines(stdout.String())), 0o600); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if normalizeLines(stdout.String()) != normalizeLines(string(want)) {
				t.Fatalf("output mismatch\nwant:\n%s\ngot:\n%s", want, stdout.String())
			}
		})
	}
}

func TestScanGoldenDiagnosticsAndUnresolved(t *testing.T) {
	server := certSpotterServer(t, scanCTFixture())
	var stdout, stderr bytes.Buffer
	code := execute([]string{"scan", "--domain", "example.com", "--source", "certspotter", "--format", "json"}, &stdout, &stderr, scanDependencies(server.URL, goldenProber()))
	if code != ExitFindingsPresent {
		t.Fatalf("exit = %d", code)
	}
	for _, code := range []string{"SCD-0008", "SCD-0010", "SCD-0011", "SCD-0013"} {
		if !strings.Contains(stderr.String(), code) {
			t.Errorf("stderr missing %s: %s", code, stderr.String())
		}
	}
	var document struct {
		Unresolved []inventory.Unresolved `json:"unresolved"`
		Sources    []string               `json:"sources_used"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Unresolved) != 1 || document.Unresolved[0].Reason != "wildcard" {
		t.Fatalf("unresolved = %v", document.Unresolved)
	}
	if strings.Join(document.Sources, ",") != "certspotter,tls" {
		t.Fatalf("sources_used = %v", document.Sources)
	}
}

// testNowScan fixes wall-clock time so certificate lifetimes and verification are deterministic.
var testNowScan = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

// selfSignedLeaf builds a self-signed leaf certificate for the loopback address.
func selfSignedLeaf(t *testing.T, names []string, lifetime time.Duration) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(0x1234),
		Subject:      pkix.Name{CommonName: firstOrName(names, "loopback")},
		DNSNames:     names,
		NotBefore:    testNowScan.Add(-time.Hour),
		NotAfter:     testNowScan.Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func firstOrName(names []string, fallback string) string {
	if len(names) > 0 {
		return names[0]
	}
	return fallback
}

func serveTLS(t *testing.T, certificate tls.Certificate) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}})
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
	return listener.Addr().(*net.TCPAddr).Port
}

func TestScanAgainstLocalTLS(t *testing.T) {
	leaf := selfSignedLeaf(t, []string{"example.com"}, 90*24*time.Hour)
	port := serveTLS(t, leaf)
	fingerprint := sha256.Sum256(leaf.Certificate[0])
	expected := hex.EncodeToString(fingerprint[:])

	// The CT record repeats the exact live fingerprint, so the certificate must
	// correlate as matched. --max-hosts 1 keeps the apex, which needs DNS, out.
	body := fmt.Sprintf(`[{"id":"1","cert_sha256":"%s","dns_names":["example.com"],"issuer":{"name":"CN=Loopback"},"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","revoked":false}]`, expected)
	server := certSpotterServer(t, body)
	var stdout, stderr bytes.Buffer
	code := execute([]string{"scan", "--domain", "example.com", "--source", "certspotter", "--host", "127.0.0.1:" + strconv.Itoa(port), "--max-hosts", "1", "--format", "json"}, &stdout, &stderr, scanDependencies(server.URL, &tlsprobe.Prober{Timeout: 3 * time.Second, Clock: clock.Fixed{Time: testNowScan}}))
	if code != ExitOK {
		t.Fatalf("exit = %d; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), expected) || !strings.Contains(stdout.String(), `"kind":"matched"`) {
		t.Fatalf("expected matched fingerprint %s in %s", expected, stdout.String())
	}

	// The same live server without CT is a live-only finding.
	stdout.Reset()
	stderr.Reset()
	code = execute([]string{"scan", "--from-ct=false", "--host", "127.0.0.1:" + strconv.Itoa(port), "--format", "json"}, &stdout, &stderr, scanDependencies(server.URL, &tlsprobe.Prober{Timeout: 3 * time.Second, Clock: clock.Fixed{Time: testNowScan}}))
	if code != ExitFindingsPresent || !strings.Contains(stdout.String(), `"kind":"live_only"`) || !strings.Contains(stdout.String(), "private_or_untrusted") {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestScanExitCodesAndValidation(t *testing.T) {
	// Usage errors.
	for _, args := range [][]string{
		{"scan"},
		{"scan", "--domain", "https://example.com"},
		{"scan", "--domain", "example.com", "--format", "xml"},
		{"scan", "--domain", "example.com", "--source", "unknown"},
		{"scan", "--domain", "example.com", "--port", "0"},
		{"scan", "--domain", "example.com", "--concurrency", "0"},
		{"scan", "--domain", "example.com", "--max-hosts", "0"},
		{"scan", "--from-ct=false"},
	} {
		var stdout, stderr bytes.Buffer
		if code := execute(args, &stdout, &stderr, scanDependencies("x", fakeProber{})); code != ExitUsageError || !strings.Contains(stderr.String(), "SCD-0001") {
			t.Fatalf("args=%v code=%d stderr=%s", args, code, stderr.String())
		}
	}

	// Every source unavailable: CT fails and the only probed host is refused.
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	code := execute([]string{"scan", "--domain", "example.com", "--host", "127.0.0.1:1", "--max-hosts", "1"}, &stdout, &stderr, scanDependencies(server.URL, &tlsprobe.Prober{Timeout: 3 * time.Second, Clock: clock.Fixed{Time: testNowScan}}))
	if code != ExitSourceUnavailable {
		t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "SCD-0002") {
		t.Fatalf("expected SCD-0002 in %s", stderr.String())
	}
}

func TestScanWildcardAndHostCap(t *testing.T) {
	wildcard := fmt.Sprintf(`[{"id":"1","cert_sha256":"%s","dns_names":["*.example.com"],"issuer":{"name":"CN=CA"},"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","revoked":false}]`, strings.Repeat("c", 64))
	server := certSpotterServer(t, wildcard)
	var stdout, stderr bytes.Buffer
	code := execute([]string{"scan", "--domain", "example.com", "--source", "certspotter", "--host", "127.0.0.1:1", "--max-hosts", "1", "--format", "json"}, &stdout, &stderr, scanDependencies(server.URL, fakeProber{failures: map[string]tlsprobe.ErrorClass{"127.0.0.1:1": tlsprobe.ClassRefused}}))
	if code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "SCD-0008") || !strings.Contains(stderr.String(), "SCD-0009") {
		t.Fatalf("stderr missing wildcard or cap diagnostics: %s", stderr.String())
	}
	var document struct {
		Unresolved []inventory.Unresolved `json:"unresolved"`
		Findings   []inventory.Finding    `json:"findings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	reasons := map[string]bool{}
	for _, unresolved := range document.Unresolved {
		reasons[unresolved.Reason] = true
	}
	if !reasons["wildcard"] || !reasons["host-cap"] {
		t.Fatalf("unresolved = %v", document.Unresolved)
	}
	if len(document.Findings) != 1 || document.Findings[0].Kind != "not_checked" {
		t.Fatalf("findings = %v", document.Findings)
	}
}

func TestScanHostsFileAndFuzz(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "hosts.txt")
	content := "# comment\n\n  www.example.com  # inline comment\nwww.example.com\n127.0.0.1:8443\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	hosts, err := readHostsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 3 {
		t.Fatalf("hosts = %v", hosts)
	}

	prober := fakeProber{results: map[string]tlsprobe.Result{
		"127.0.0.1:8443": {Fingerprint: strings.Repeat("f", 64), Names: []string{"example.com"}, Issuer: "CN=Live", NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), Trusted: true},
	}}
	var stdout, stderr bytes.Buffer
	code := execute([]string{"scan", "--from-ct=false", "--hosts-file", path, "--format", "json"}, &stdout, &stderr, scanDependencies("x", prober))
	if code != ExitFindingsPresent {
		t.Fatalf("exit = %d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var document struct {
		ProbeErrors  []inventory.ProbeError  `json:"probe_errors"`
		Certificates []inventory.Certificate `json:"certificates"`
		Findings     []inventory.Finding     `json:"findings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("exit=%d stdout=%q stderr=%q: %v", code, stdout.String(), stderr.String(), err)
	}
	if len(document.ProbeErrors) != 1 || len(document.Certificates) != 1 {
		t.Fatalf("probe_errors=%v certificates=%v", document.ProbeErrors, document.Certificates)
	}
	if len(document.Findings) != 1 || document.Findings[0].Kind != "live_only" {
		t.Fatalf("findings = %v", document.Findings)
	}
}

func FuzzParseHostsFile(f *testing.F) {
	for _, seed := range []string{"example.com\n", "# c\n\nhost:8443\n", "", "\n\n", "a#b", "  spaced  \n"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data string) {
		hosts, err := parseHostsFile(strings.NewReader(data))
		if err != nil {
			return
		}
		for _, host := range hosts {
			if strings.TrimSpace(host) != host || host == "" || strings.Contains(host, "#") {
				t.Fatalf("invalid host %q from %q", host, data)
			}
		}
	})
}
