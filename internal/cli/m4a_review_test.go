package cli

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/inventory"
	"github.com/HarnageaGabriel/scadenza/internal/kube"
	"github.com/HarnageaGabriel/scadenza/internal/tlsprobe"
)

func sourceCoverage(documentBytes []byte) map[string]inventory.SourceCoverage {
	var document struct {
		Coverage inventory.Coverage `json:"coverage"`
	}
	if err := json.Unmarshal(documentBytes, &document); err != nil {
		panic(err)
	}
	result := map[string]inventory.SourceCoverage{}
	for _, source := range document.Coverage.Sources {
		result[source.Name] = source
	}
	return result
}

func TestScanDefaultSourcesStrictTreatsFallbackAsNotRequested(t *testing.T) {
	body := fmt.Sprintf(`[{"id":"1","cert_sha256":"%s","dns_names":["example.com"],"issuer":{"name":"CN=Example Root"},"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","revoked":false}]`, strings.Repeat("a", 64))
	server := certSpotterServer(t, body)
	prober := fakeProber{results: map[string]tlsprobe.Result{
		"example.com:443": {
			Fingerprint: strings.Repeat("a", 64), Names: []string{"example.com"},
			Issuer: "CN=Example Root", NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), Trusted: true,
		},
	}}
	var stdout, stderr bytes.Buffer
	code := execute([]string{"scan", "--domain", "example.com", "--fail-on", "none", "--strict", "--format", "json"},
		&stdout, &stderr, scanDependencies(server.URL, prober))
	if code != ExitOK {
		t.Fatalf("exit = %d; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	sources := sourceCoverage(stdout.Bytes())
	if sources["certspotter"].Status != inventory.SourceStatusOK || sources["certspotter"].Detail != "queried" {
		t.Fatalf("certspotter = %+v", sources["certspotter"])
	}
	if sources["crtsh"].Status != inventory.SourceStatusNotRequested ||
		sources["crtsh"].Detail != "not needed: earlier source answered" {
		t.Fatalf("crtsh = %+v", sources["crtsh"])
	}
	if sources["tls"].Status != inventory.SourceStatusOK || sources["tls"].Detail == "" {
		t.Fatalf("tls = %+v", sources["tls"])
	}
}

func TestScanCTSourcePartialFailsStrict(t *testing.T) {
	body := fmt.Sprintf(`[{"id":"1","cert_sha256":"%s","dns_names":["first.example.com","second.example.com"],"issuer":{"name":"CN=Example Root"},"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","revoked":false}]`, strings.Repeat("a", 64))
	crtBody := `[{"issuer_ca_id":1,"issuer_name":"Example crt.sh CA","common_name":"","name_value":"first.example.com\\nsecond.example.com","id":1,"not_before":"2026-01-01T00:00:00","not_after":"2026-04-01T00:00:00","serial_number":"ABC","result_count":1}]`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/cert":
			if request.URL.Query().Get("domain") == "first.example.com" {
				writer.WriteHeader(http.StatusBadGateway)
				return
			}
			if request.URL.Query().Get("after") != "" {
				_, _ = writer.Write([]byte("[]"))
				return
			}
			_, _ = writer.Write([]byte(body))
		case "/crt":
			_, _ = writer.Write([]byte(crtBody))
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	prober := fakeProber{results: map[string]tlsprobe.Result{
		"first.example.com:443": {
			Fingerprint: strings.Repeat("a", 64), Names: []string{"first.example.com", "second.example.com"},
			Issuer: "CN=Example Root", NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), Trusted: true,
		},
		"second.example.com:443": {
			Fingerprint: strings.Repeat("a", 64), Names: []string{"first.example.com", "second.example.com"},
			Issuer: "CN=Example Root", NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), Trusted: true,
		},
	}}
	dependencies := testCTDependencies(server.URL+"/cert", server.URL+"/crt")
	dependencies.prober = prober
	var stdout, stderr bytes.Buffer
	code := execute([]string{
		"scan", "--domain", "first.example.com", "--domain", "second.example.com",
		"--fail-on", "none", "--strict", "--format", "json",
	}, &stdout, &stderr, dependencies)
	if code != ExitIncompleteScan {
		s := sourceCoverage(stdout.Bytes())
		t.Fatalf("exit = %d; certspotter=%s/%s crtsh=%s/%s", code, s["certspotter"].Status, s["certspotter"].Detail, s["crtsh"].Status, s["crtsh"].Detail)
	}
	sources := sourceCoverage(stdout.Bytes())
	if sources["certspotter"].Status != inventory.SourceStatusPartial ||
		sources["certspotter"].Detail != "1 succeeded, 1 failed" {
		t.Fatalf("certspotter = %+v", sources["certspotter"])
	}
	if sources["crtsh"].Status != inventory.SourceStatusOK || sources["crtsh"].Detail != "queried" {
		t.Fatalf("crtsh = %+v", sources["crtsh"])
	}
}

func TestScanKubeProblemMarksPartial(t *testing.T) {
	result := kube.Result{Problems: []kube.Problem{{Code: kube.CodeCRDMissing, Resource: "certificates"}}}
	var stdout, stderr bytes.Buffer
	code := execute([]string{"scan", "--kube", "--fail-on", "none", "--strict", "--format", "json"},
		&stdout, &stderr, scanKubeDependencies("x", fakeProber{}, fakeKubeSource{result: result}, nil))
	if code != ExitIncompleteScan {
		t.Fatalf("exit = %d; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	sources := sourceCoverage(stdout.Bytes())
	if sources["kube"].Status != inventory.SourceStatusPartial ||
		sources["kube"].Detail != "1 problem(s) recorded" {
		t.Fatalf("kube = %+v", sources["kube"])
	}
}

func TestIncompleteScanCoversSourceHealthWhenNoTargetsAreRequested(t *testing.T) {
	cases := []struct {
		name    string
		sources []inventory.SourceCoverage
		want    bool
	}{
		{"failed requested source", []inventory.SourceCoverage{{Name: "kube", Status: inventory.SourceStatusFailed}}, true},
		{"partial requested source", []inventory.SourceCoverage{{Name: "kube", Status: inventory.SourceStatusPartial}}, true},
		{"ok requested source", []inventory.SourceCoverage{{Name: "kube", Status: inventory.SourceStatusOK}}, false},
		{"no source produced data", []inventory.SourceCoverage{{Name: "kube", Status: inventory.SourceStatusNotRequested}}, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			coverage := inventory.NewCoverage(0, 0, 0, 0, test.sources)
			_, incomplete := incompleteScan(false, 100, coverage, nil, nil)
			if incomplete != test.want {
				t.Fatalf("incomplete = %v, want %v; coverage=%+v", incomplete, test.want, coverage)
			}
		})
	}
}

func TestMaskedIncompleteScanEmitsWarningSCD0020(t *testing.T) {
	t.Run("blocking finding wins", func(t *testing.T) {
		server := certSpotterServer(t, scanCTFixture())
		var stdout, stderr bytes.Buffer
		code := execute([]string{
			"scan", "--domain", "example.com", "--source", "certspotter",
			"--fail-on", "live_only", "--strict", "--format", "json",
		},
			&stdout, &stderr, scanDependencies(server.URL, goldenProber()))
		if code != ExitFindingsPresent {
			t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), `"code":"SCD-0020"`) ||
			!strings.Contains(stdout.String(), `"severity":"warning"`) {
			t.Fatalf("document missing warning SCD-0020: %s", stdout.String())
		}
		if !strings.Contains(stderr.String(), "warning [SCD-0020]") {
			t.Fatalf("stderr missing warning SCD-0020: %s", stderr.String())
		}
	})

	t.Run("source unavailable wins", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusBadGateway)
		}))
		defer server.Close()
		var stdout, stderr bytes.Buffer
		code := execute([]string{
			"scan", "--domain", "example.com", "--source", "certspotter",
			"--fail-on", "none", "--strict", "--format", "json",
		},
			&stdout, &stderr, scanDependencies(server.URL, fakeProber{}))
		if code != ExitSourceUnavailable {
			t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), `"code":"SCD-0020"`) ||
			!strings.Contains(stderr.String(), "warning [SCD-0020]") {
			t.Fatalf("missing warning SCD-0020: stdout=%s stderr=%s", stdout.String(), stderr.String())
		}
	})
}

func TestScanNowPropagatesEvaluationClock(t *testing.T) {
	leaf := selfSignedLeaf(t, []string{"example.com"}, 90*24*time.Hour)
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	port := serveTLS(t, leaf)
	prober := &tlsprobe.Prober{Timeout: 3 * time.Second, Resolver: loopbackResolver{}, Roots: roots}
	var stdout, stderr bytes.Buffer
	code := execute([]string{
		"scan", "--from-ct=false", "--domain", "example.com",
		"--port", strconv.Itoa(port), "--now", testNowScan.Format(time.RFC3339),
		"--fail-on", "none", "--format", "json",
	}, &stdout, &stderr, scanDependencies("x", prober))
	if code != ExitOK {
		t.Fatalf("exit = %d; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var document struct {
		Certificates []inventory.Certificate `json:"certificates"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Certificates) != 1 || document.Certificates[0].Public == nil ||
		!*document.Certificates[0].Public {
		t.Fatalf("evaluation clock was not used for TLS verification: %+v", document.Certificates)
	}
}

func TestScanPassesEvaluationClockToKube(t *testing.T) {
	var options kube.Options
	dependencies := scanDependencies("x", fakeProber{})
	dependencies.loadKube = func(_ kube.LoadOptions, scan kube.Options) (kube.Source, error) {
		options = scan
		return fakeKubeSource{}, nil
	}
	var stdout, stderr bytes.Buffer
	code := execute([]string{"scan", "--kube", "--now", testNowScan.Format(time.RFC3339), "--format", "json"},
		&stdout, &stderr, dependencies)
	if code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
	}
	if options.Clock == nil || !options.Clock.Now().Equal(testNowScan) {
		t.Fatalf("kube clock = %v, want %v", options.Clock, testNowScan)
	}
}

func TestTargetKeyDistinguishesPorts(t *testing.T) {
	if targetKey(probeTarget{host: "example.com", port: 443}) ==
		targetKey(probeTarget{host: "example.com", port: 8443}) {
		t.Fatal("same host on different ports must have different keys")
	}
}

func TestScanRejectsEmptyFailOnList(t *testing.T) {
	for _, value := range []string{"", "   ", ","} {
		var stdout, stderr bytes.Buffer
		code := execute([]string{"scan", "--domain", "example.com", "--fail-on", value, "--format", "json"},
			&stdout, &stderr, scanDependencies("x", fakeProber{}))
		if code != ExitUsageError || !strings.Contains(stderr.String(), "SCD-0021") {
			t.Fatalf("--fail-on %q: exit=%d stderr=%s", value, code, stderr.String())
		}
	}
}
