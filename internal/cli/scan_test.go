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
	"github.com/HarnageaGabriel/scadenza/internal/kube"
	"github.com/HarnageaGabriel/scadenza/internal/owner"
	"github.com/HarnageaGabriel/scadenza/internal/tlsprobe"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// loopbackResolver resolves every host name to the loopback address without
// touching DNS, so probe tests stay hermetic.
type loopbackResolver struct{}

func (loopbackResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
}

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
	// correlate as matched. The apex "example.com" is an explicit target, so it
	// is probed (never trimmed by --max-hosts) and resolved to loopback instead
	// of performing a real DNS lookup.
	body := fmt.Sprintf(`[{"id":"1","cert_sha256":"%s","dns_names":["example.com"],"issuer":{"name":"CN=Loopback"},"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","revoked":false}]`, expected)
	server := certSpotterServer(t, body)
	prober := &tlsprobe.Prober{Timeout: 3 * time.Second, Clock: clock.Fixed{Time: testNowScan}, Resolver: loopbackResolver{}}
	var stdout, stderr bytes.Buffer
	code := execute([]string{"scan", "--domain", "example.com", "--source", "certspotter", "--host", "127.0.0.1", "--port", strconv.Itoa(port), "--format", "json"}, &stdout, &stderr, scanDependencies(server.URL, prober))
	if code != ExitOK {
		t.Fatalf("exit = %d; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), expected) || !strings.Contains(stdout.String(), `"kind":"matched"`) {
		t.Fatalf("expected matched fingerprint %s in %s", expected, stdout.String())
	}

	// The same live server without CT is a live-only finding.
	stdout.Reset()
	stderr.Reset()
	code = execute([]string{"scan", "--from-ct=false", "--host", "127.0.0.1:" + strconv.Itoa(port), "--format", "json"}, &stdout, &stderr, scanDependencies(server.URL, prober))
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

	// Every external source unavailable: both CT sources fail. The document is
	// still rendered (including probe_errors) before exit 4 is returned, and a
	// fallback that never succeeded is not reported.
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()
	prober := &tlsprobe.Prober{Timeout: 3 * time.Second, Clock: clock.Fixed{Time: testNowScan}, Resolver: loopbackResolver{}}
	var stdout, stderr bytes.Buffer
	code := execute([]string{"scan", "--domain", "example.com", "--host", "127.0.0.1:1", "--format", "json"}, &stdout, &stderr, scanDependencies(server.URL, prober))
	if code != ExitSourceUnavailable {
		t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "SCD-0002") {
		t.Fatalf("expected SCD-0002 in %s", stderr.String())
	}
	if strings.Contains(stderr.String(), "SCD-0007") {
		t.Fatalf("unexpected fallback diagnostic when every source failed: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), `"schema_version"`) || !strings.Contains(stdout.String(), "probe_errors") {
		t.Fatalf("document was not rendered before exit 4: %q", stdout.String())
	}

	// With --from-ct=false no external source was selected, so a total probe
	// failure is not exit 4: the document is still rendered and the code follows
	// the findings.
	stdout.Reset()
	stderr.Reset()
	code = execute([]string{"scan", "--from-ct=false", "--host", "127.0.0.1:1", "--format", "json"}, &stdout, &stderr, scanDependencies(server.URL, prober))
	if code != ExitOK {
		t.Fatalf("exit = %d; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "probe_errors") {
		t.Fatalf("expected probe_errors in %q", stdout.String())
	}
}

func TestScanWildcardAndHostCap(t *testing.T) {
	// A wildcard plus two derived names capped to one: the wildcard is never
	// probed and the alphabetically last derived name is dropped as host-cap.
	body := fmt.Sprintf(`[
{"id":"1","cert_sha256":"%s","dns_names":["*.example.com"],"issuer":{"name":"CN=CA"},"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","revoked":false},
{"id":"2","cert_sha256":"%s","dns_names":["api.example.com"],"issuer":{"name":"CN=CA"},"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","revoked":false},
{"id":"3","cert_sha256":"%s","dns_names":["shop.example.com"],"issuer":{"name":"CN=CA"},"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","revoked":false}
]`, strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64))
	server := certSpotterServer(t, body)
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
	byReason := map[string]string{}
	reasons := map[string]bool{}
	for _, unresolved := range document.Unresolved {
		reasons[unresolved.Reason] = true
		byReason[unresolved.Name] = unresolved.Reason
	}
	if !reasons["wildcard"] || !reasons["host-cap"] {
		t.Fatalf("unresolved = %v", document.Unresolved)
	}
	if byReason["shop.example.com"] != "host-cap" || byReason["api.example.com"] != "" {
		t.Fatalf("capped hosts = %v", document.Unresolved)
	}
	if len(document.Findings) == 0 {
		t.Fatal("expected findings")
	}
	for _, finding := range document.Findings {
		if finding.Kind != "not_checked" {
			t.Fatalf("finding %v is not not_checked", finding)
		}
	}
}

// TestScanMaxHostsKeepsExplicitTargets proves that --max-hosts trims only
// Certificate Transparency derived hosts and never an explicitly named target.
func TestScanMaxHostsKeepsExplicitTargets(t *testing.T) {
	body := fmt.Sprintf(`[
{"id":"1","cert_sha256":"%s","dns_names":["d.example.com"],"issuer":{"name":"CN=CA"},"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","revoked":false},
{"id":"2","cert_sha256":"%s","dns_names":["e.example.com"],"issuer":{"name":"CN=CA"},"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","revoked":false},
{"id":"3","cert_sha256":"%s","dns_names":["f.example.com"],"issuer":{"name":"CN=CA"},"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","revoked":false}
]`, strings.Repeat("d", 64), strings.Repeat("e", 64), strings.Repeat("f", 64))
	server := certSpotterServer(t, body)
	var stdout, stderr bytes.Buffer
	// The explicit host sorts after every derived name, so it would be dropped
	// first if the cap were applied to the whole target list.
	code := execute([]string{"scan", "--domain", "example.com", "--source", "certspotter", "--host", "zzz.example.test:1", "--max-hosts", "1", "--format", "json"}, &stdout, &stderr, scanDependencies(server.URL, fakeProber{failures: map[string]tlsprobe.ErrorClass{"zzz.example.test:1": tlsprobe.ClassRefused}}))
	if code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
	}
	var document struct {
		Unresolved  []inventory.Unresolved `json:"unresolved"`
		ProbeErrors []inventory.ProbeError `json:"probe_errors"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if !probedHost(document.ProbeErrors, "zzz.example.test") {
		t.Fatalf("explicit target was displaced by --max-hosts: %v", document.ProbeErrors)
	}
	capped := map[string]bool{}
	for _, unresolved := range document.Unresolved {
		if unresolved.Reason == "host-cap" {
			capped[unresolved.Name] = true
		}
	}
	if len(capped) != 2 || !capped["e.example.com"] || !capped["f.example.com"] {
		t.Fatalf("host-cap names = %v", document.Unresolved)
	}
}

func probedHost(probeErrors []inventory.ProbeError, host string) bool {
	for _, probeError := range probeErrors {
		if probeError.Host == host {
			return true
		}
	}
	return false
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

// --- M3: Kubernetes source -------------------------------------------------

// fakeKubeSource is a scripted kube.Source. It never touches a cluster, so the
// cobra wiring, correlation, rendering, and exit codes are exercised end to end
// without a real API server.
type fakeKubeSource struct {
	result kube.Result
	err    error
}

func TestScanKubeClientErrorsNeverLeakRawText(t *testing.T) {
	const secret = "token=fake-token\n-----BEGIN PRIVATE KEY-----\nfake-pem\n-----END PRIVATE KEY-----"
	source := fakeKubeSource{
		result: kube.Result{Problems: []kube.Problem{{Code: kube.CodeUnreachable, Resource: "secrets", Namespace: "payments", HTTPStatus: 401, Reason: metav1.StatusReasonUnauthorized, Detail: secret}}},
		err:    errors.New(secret),
	}
	var stdout, stderr bytes.Buffer
	code := execute([]string{"scan", "--kube", "--format", "json"}, &stdout, &stderr, scanKubeDependencies("x", fakeProber{}, source, nil))
	if code != ExitSourceUnavailable {
		t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "fake-token") || strings.Contains(stdout.String(), "PRIVATE KEY") || strings.Contains(stderr.String(), "fake-token") || strings.Contains(stderr.String(), "PRIVATE KEY") {
		t.Fatalf("secret leaked; stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	var document map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
}

func (source fakeKubeSource) Scan(context.Context) (kube.Result, error) {
	return source.result, source.err
}

// scanKubeDependencies wires a fake Kubernetes source into the scan command.
// loadErr models a client-load failure such as an unreachable API server.
func scanKubeDependencies(certURL string, prober hostProber, source kube.Source, loadErr error) ctDependencies {
	dependencies := scanDependencies(certURL, prober)
	dependencies.loadKube = func(kube.LoadOptions, kube.Options) (kube.Source, error) {
		if loadErr != nil {
			return nil, loadErr
		}
		return source, nil
	}
	return dependencies
}

// kubeFixture returns one TLS Secret certificate and one cert-manager
// Certificate, plus a non-fatal CRD-missing problem.
func kubeFixture() kube.Result {
	verified := true
	return kube.Result{
		Certificates: []kube.Certificate{
			{
				Fingerprint: strings.Repeat("e", 64),
				DedupKey:    "secret/payments/api-tls",
				Serial:      "1e",
				Names:       []string{"api.payments.example.com"},
				Issuer:      "CN=Payments Internal CA",
				NotBefore:   time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC),
				NotAfter:    time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC),
				Owners:      []owner.Owner{{Value: "team-pay", Source: owner.SourceNamespaceLabel, Location: "namespace/payments"}},
				Observations: []kube.Observation{{
					Source:     kube.SourceSecret,
					Location:   "payments/api-tls",
					Detail:     "kubernetes.io/tls secret",
					Kubernetes: &kube.Kubernetes{Resource: "secret", Namespace: "payments", Name: "api-tls"},
				}},
			},
			{
				Fingerprint: strings.Repeat("f", 64),
				DedupKey:    "certificate/shop/web",
				Serial:      "1f",
				Names:       []string{"shop.example.com"},
				Issuer:      "CN=Example Public CA",
				NotBefore:   time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC),
				NotAfter:    time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC),
				Public:      &verified,
				Owners:      []owner.Owner{{Value: "team-web", Source: owner.SourceMappingFile, Location: "domains/example.com"}},
				Observations: []kube.Observation{{
					Source:   kube.SourceCertManager,
					Location: "shop/web",
					Detail:   "Certificate -> secret web-tls",
					Kubernetes: &kube.Kubernetes{
						Resource:    "certificate",
						Namespace:   "shop",
						Name:        "web",
						SecretName:  "web-tls",
						IssuerKind:  kube.ClusterIssuerKind,
						IssuerName:  "letsencrypt",
						IssuerType:  kube.IssuerTypeACME,
						ACMEServer:  "https://acme-v02.api.letsencrypt.org/directory",
						Duration:    "2160h0m0s",
						RenewBefore: "720h0m0s",
						NotAfter:    "2026-04-10T00:00:00Z",
						RenewalTime: "2026-03-11T00:00:00Z",
						Ready:       "True",
						ReadyReason: "Ready",
					},
				}},
			},
		},
		Problems: []kube.Problem{{Code: kube.CodeCRDMissing, Resource: "cert-manager.io/v1", Detail: "certificates.cert-manager.io not found"}},
	}
}

func TestScanKubeGoldenJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := execute([]string{"scan", "--kube", "--format", "json"}, &stdout, &stderr, scanKubeDependencies("x", fakeProber{}, fakeKubeSource{result: kubeFixture()}, nil))
	if code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), kube.CodeCRDMissing) {
		t.Fatalf("missing CRD diagnostic in stderr: %s", stderr.String())
	}
	path := filepath.Join("..", "..", "testdata", "golden", "scan-kube.json.golden")
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

	// Determinism: a second identical run must produce byte-identical output.
	var repeat, repeatErr bytes.Buffer
	if code := execute([]string{"scan", "--kube", "--format", "json"}, &repeat, &repeatErr, scanKubeDependencies("x", fakeProber{}, fakeKubeSource{result: kubeFixture()}, nil)); code != ExitOK {
		t.Fatalf("repeat exit = %d", code)
	}
	if normalizeLines(repeat.String()) != normalizeLines(stdout.String()) {
		t.Fatal("kube output is not deterministic")
	}
}

func TestScanKubePartialFailureIsNotExitFour(t *testing.T) {
	server := certSpotterServer(t, scanCTFixture())
	var stdout, stderr bytes.Buffer
	code := execute([]string{"scan", "--domain", "example.com", "--source", "certspotter", "--kube", "--format", "json"},
		&stdout, &stderr, scanKubeDependencies(server.URL, fakeProber{}, fakeKubeSource{}, errors.New("dial tcp: connection refused")))
	if code == ExitSourceUnavailable {
		t.Fatalf("partial Kubernetes failure must not exit 4; stderr=%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), kube.CodeUnreachable) {
		t.Fatalf("expected %s in %s", kube.CodeUnreachable, stderr.String())
	}
}

func TestScanKubeAllSourcesFail(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := execute([]string{"scan", "--kube", "--format", "json"},
		&stdout, &stderr, scanKubeDependencies("x", fakeProber{}, nil, errors.New("no configuration has been provided")))
	if code != ExitSourceUnavailable {
		t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), kube.CodeUnreachable) {
		t.Fatalf("expected %s in %s", kube.CodeUnreachable, stderr.String())
	}
}

func TestScanKubeOwnershipFile(t *testing.T) {
	valid := filepath.Join(t.TempDir(), "owners.yaml")
	if err := os.WriteFile(valid, []byte("labelKeys:\n  - scadenza.io/owner\ndomains:\n  example.com: team-web\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := execute([]string{"scan", "--kube", "--ownership-file", valid, "--format", "json"},
		&stdout, &stderr, scanKubeDependencies("x", fakeProber{}, fakeKubeSource{result: kubeFixture()}, nil))
	if code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "team-web") || !strings.Contains(stdout.String(), `"owner_source":"mapping-file"`) {
		t.Fatalf("ownership output missing: %s", stdout.String())
	}

	invalid := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(invalid, []byte("labelKeys: [scadenza.io/owner]\nbogus: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var badOut, badErr bytes.Buffer
	code = execute([]string{"scan", "--kube", "--ownership-file", invalid, "--format", "json"},
		&badOut, &badErr, scanKubeDependencies("x", fakeProber{}, fakeKubeSource{}, nil))
	if code != ExitUsageError || !strings.Contains(badErr.String(), kube.CodeOwnershipFileInvalid) {
		t.Fatalf("invalid ownership file: code=%d stderr=%s", code, badErr.String())
	}

	missing := filepath.Join(t.TempDir(), "absent.yaml")
	code = execute([]string{"scan", "--kube", "--ownership-file", missing, "--format", "json"},
		&badOut, &badErr, scanKubeDependencies("x", fakeProber{}, fakeKubeSource{}, nil))
	if code != ExitUsageError {
		t.Fatalf("missing ownership file: code=%d", code)
	}
}

func TestScanKubeFlagsRequireKube(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "--domain", "example.com", "--kube-context", "prod"},
		{"scan", "--domain", "example.com", "--kubeconfig", "/tmp/kubeconfig"},
		{"scan", "--domain", "example.com", "--namespace", "payments"},
		{"scan", "--domain", "example.com", "--ownership-file", "owners.yaml"},
		{"scan", "--domain", "example.com", "--kube-secrets"},
		{"scan", "--kube", "--kube-qps", "0"},
		{"scan", "--domain", "example.com", "--kube-qps", "1"},
	} {
		var stdout, stderr bytes.Buffer
		if code := execute(args, &stdout, &stderr, scanKubeDependencies("x", fakeProber{}, fakeKubeSource{}, nil)); code != ExitUsageError || !strings.Contains(stderr.String(), "SCD-0001") {
			t.Fatalf("args=%v code=%d stderr=%s", args, code, stderr.String())
		}
	}
}

func TestScanKubePassesNamespacesAndRate(t *testing.T) {
	var load kube.LoadOptions
	var options kube.Options
	dependencies := scanDependencies("x", fakeProber{})
	dependencies.loadKube = func(load0 kube.LoadOptions, scan0 kube.Options) (kube.Source, error) {
		load, options = load0, scan0
		return fakeKubeSource{}, nil
	}
	var stdout, stderr bytes.Buffer
	code := execute([]string{"scan", "--kube", "--namespace", "payments", "--namespace", "shop", "--kube-context", "prod", "--kube-qps", "9", "--format", "json"},
		&stdout, &stderr, dependencies)
	if code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
	}
	if load.Context != "prod" || load.QPS != 9 {
		t.Fatalf("load options = %+v", load)
	}
	if len(options.Namespaces) != 2 || options.Namespaces[0] != "payments" || options.Namespaces[1] != "shop" {
		t.Fatalf("namespaces = %v", options.Namespaces)
	}
	if keys := options.Owners.LabelKeys(); len(keys) != 1 || keys[0] != "scadenza.io/owner" {
		t.Fatalf("default label keys = %v", keys)
	}
	if options.Secrets {
		t.Fatal("default -- kube must not read Secret data")
	}
}

func TestScanKubeSecretsFlagAndDiagnostic(t *testing.T) {
	var options kube.Options
	dependencies := scanDependencies("x", fakeProber{})
	dependencies.loadKube = func(_ kube.LoadOptions, scan0 kube.Options) (kube.Source, error) {
		options = scan0
		return fakeKubeSource{}, nil
	}
	var stdout, stderr bytes.Buffer
	code := execute([]string{
		"scan", "--kube", "--kube-secrets", "--namespace", "shop", "--namespace", "payments",
		"--format", "json",
	}, &stdout, &stderr, dependencies)
	if code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
	}
	if !options.Secrets {
		t.Fatal("--kube-secrets did not enable Options.Secrets")
	}
	if !strings.Contains(stderr.String(), "SCD-0028") ||
		!strings.Contains(stderr.String(), "namespaces=payments,shop") {
		t.Fatalf("missing Secret-data diagnostic: %s", stderr.String())
	}
}

func TestKubeSecretNamespaceDetail(t *testing.T) {
	if got := kubeSecretNamespaceDetail([]string{"", "  "}); got != "all" {
		t.Fatalf("empty namespace scope = %q, want all", got)
	}
	if got := kubeSecretNamespaceDetail([]string{"shop", "payments", "shop"}); got != "payments,shop" {
		t.Fatalf("namespace scope = %q, want payments,shop", got)
	}
}

// TestParseHostsFileStripsBOM proves a UTF-8 BOM at the start of the file does
// not become part of the first host name.
func TestParseHostsFileStripsBOM(t *testing.T) {
	hosts, err := parseHostsFile(strings.NewReader("\ufeffexample.com\n# comment\napi.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 || hosts[0] != "example.com" || hosts[1] != "api.example.com" {
		t.Fatalf("hosts = %v", hosts)
	}
}

// TestDeriveHostsUsesConfiguredPort proves CT-derived hosts are probed on the
// configured --port instead of a hardcoded 443.
func TestDeriveHostsUsesConfiguredPort(t *testing.T) {
	records := []ct.Certificate{{SubjectNames: []string{"www.example.com", "*.example.com", "other.test"}}}
	targets, wildcards := deriveHosts(records, []string{"example.com"}, 8443)
	if len(targets) != 1 || targets[0].host != "www.example.com" || targets[0].port != 8443 {
		t.Fatalf("targets = %+v", targets)
	}
	if len(wildcards) != 1 || wildcards[0] != "*.example.com" {
		t.Fatalf("wildcards = %v", wildcards)
	}
}

// TestScanFallbackDiagnosticOnlyAfterSuccess proves SCD-0007 is emitted when the
// first selected CT source fails and the next one answers, and (in
// TestScanExitCodesAndValidation) that it is not emitted when every source
// fails.
func TestScanFallbackDiagnosticOnlyAfterSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.Contains(request.URL.Path, "cert") {
			writer.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = writer.Write([]byte(crtSHOne))
	}))
	defer server.Close()
	dependencies := testCTDependencies(server.URL+"/cert", server.URL+"/crt")
	dependencies.prober = fakeProber{}
	var stdout, stderr bytes.Buffer
	code := execute([]string{"scan", "--domain", "example.com", "--source", "certspotter,crtsh", "--host", "127.0.0.1:1", "--format", "json"}, &stdout, &stderr, dependencies)
	if code == ExitSourceUnavailable {
		t.Fatalf("a successful fallback must not be exit 4; stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "SCD-0002") {
		t.Fatalf("expected the failed source diagnostic: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "SCD-0007") {
		t.Fatalf("expected the fallback diagnostic after the fallback succeeded: %s", stderr.String())
	}
}
