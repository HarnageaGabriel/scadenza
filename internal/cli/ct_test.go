package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/clock"
	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/httpx"
)

const (
	certSpotterOne = `[{"id":"1","cert_sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","dns_names":["www.example.com","example.com","api.example.com","mail.example.com"],"issuer":{"friendly_name":"Example CA","name":"CN=Example Root"},"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-02T00:00:00Z","revoked":false}]`
	crtSHOne       = `[{"issuer_ca_id":10,"issuer_name":"Example crt.sh CA","common_name":"example.com","name_value":"example.com\nwww.example.com","id":2,"entry_timestamp":"2026-01-01T00:00:00","not_before":"2026-01-01T00:00:00","not_after":"2026-05-01T00:00:00","serial_number":"ABC","result_count":1}]`
)

func TestCTGoldenFormats(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.URL.Query().Get("after") != "" {
			_, _ = writer.Write([]byte("[]"))
			return
		}
		_, _ = writer.Write([]byte(certSpotterOne))
	}))
	defer server.Close()
	dependencies := testCTDependencies(server.URL, server.URL)
	for _, format := range []string{"table", "json", "csv"} {
		t.Run(format, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := execute(context.Background(), []string{"ct", "Example.COM", "--source", "certspotter", "--format", format}, &stdout, &stderr, dependencies)
			if code != ExitOK {
				t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
			}
			want, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "ct."+format+".golden"))
			if err != nil {
				t.Fatal(err)
			}
			if normalizeLines(stdout.String()) != normalizeLines(string(want)) {
				t.Fatalf("output mismatch\nwant:\n%s\ngot:\n%s", want, stdout.String())
			}
		})
	}
}

func TestCTFallbackAndFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/cert":
			writer.WriteHeader(http.StatusTooManyRequests)
			_, _ = writer.Write([]byte(`{"error":"rate_limited"}`))
		case "/crt":
			_, _ = writer.Write([]byte(crtSHOne))
		default:
			writer.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	code := execute(context.Background(), []string{"ct", "example.com", "--format", "json"}, &stdout, &stderr, testCTDependencies(server.URL+"/cert", server.URL+"/crt"))
	if code != ExitOK || !strings.Contains(stderr.String(), "SCD-0003") || !strings.Contains(stderr.String(), "SCD-0007") || !strings.Contains(stdout.String(), `"source":"crtsh"`) {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = execute(context.Background(), []string{"ct", "example.com"}, &stdout, &stderr, testCTDependencies(server.URL+"/fail", server.URL+"/fail"))
	if code != ExitSourceUnavailable || !strings.Contains(stderr.String(), "SCD-0002") {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
}

func TestCTValidation(t *testing.T) {
	for _, args := range [][]string{{"ct", "https://example.com"}, {"ct", "example.com", "--format", "xml"}, {"ct", "example.com", "--source", "unknown"}, {"ct", "example.com", "--max-results", "0"}} {
		var stdout, stderr bytes.Buffer
		if code := execute(context.Background(), args, &stdout, &stderr, testCTDependencies("x", "x")); code != ExitUsageError || !strings.Contains(stderr.String(), "SCD-0001") {
			t.Fatalf("args=%v code=%d stderr=%s", args, code, stderr.String())
		}
	}
}

func testCTDependencies(certURL, crtURL string) ctDependencies {
	client := func() *httpx.Client {
		return &httpx.Client{HTTP: http.DefaultClient, UserAgent: "test", MaxAttempts: 1, Sleep: func(context.Context, time.Duration) error { return nil }}
	}
	return ctDependencies{clock: clock.Fixed{Time: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)}, sources: map[string]ct.Source{"certspotter": &ct.CertSpotter{Client: client(), URL: certURL}, "crtsh": &ct.CrtSH{Client: client(), URL: crtURL}}}
}
func normalizeLines(value string) string { return strings.ReplaceAll(value, "\r\n", "\n") }

func TestExitCodeClassification(t *testing.T) {
	if got := exitCode(errors.New("plain")); got != ExitInternalError {
		t.Fatalf("untyped error exit = %d", got)
	}
	if got := exitCode(fmt.Errorf("wrapped: %w", &commandError{code: ExitUsageError})); got != ExitUsageError {
		t.Fatalf("typed error exit = %d", got)
	}
	for _, args := range [][]string{{"ct"}, {"ct", "a", "b"}, {"ct", "example.com", "--bogus"}, {"nosuch"}, {"version", "extra"}} {
		var stdout, stderr bytes.Buffer
		if code := execute(context.Background(), args, &stdout, &stderr, testCTDependencies("x", "x")); code != ExitUsageError {
			t.Errorf("args=%v code=%d", args, code)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := execute(context.Background(), []string{"ct", "example.com", "--format", "csv"}, &stdout, &stderr, ctDependencies{clock: clock.Fixed{}, sources: map[string]ct.Source{"certspotter": failingSource{}, "crtsh": failingSource{}}}); code != ExitSourceUnavailable {
		t.Errorf("source failure code=%d", code)
	}
}

type failingSource struct{}

func (failingSource) Name() string { return "certspotter" }
func (failingSource) Search(context.Context, ct.Query) ([]ct.Certificate, error) {
	return nil, errors.New("down")
}
