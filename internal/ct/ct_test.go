package ct

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/httpx"
)

func TestNormalizeDomain(t *testing.T) {
	// Cases derive from UTS #46 processing documented by golang.org/x/net/idna and command constraints.
	tests := []struct {
		input, want string
		invalid     bool
	}{
		{input: "Example.COM", want: "example.com"},
		{input: "*.example.com", want: "example.com"},
		{input: "bücher.example", want: "xn--bcher-kva.example"},
		{input: "https://example.com", invalid: true},
		{input: "127.0.0.1", invalid: true},
		{input: "a.*.example", invalid: true},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, err := NormalizeDomain(test.input)
			if (err != nil) != test.invalid || got != test.want {
				t.Fatalf("NormalizeDomain(%q) = %q, %v", test.input, got, err)
			}
		})
	}
}

func TestDecodeFixtures(t *testing.T) {
	// Recorded response: testdata/ct/certspotter-example.com.raw.json.
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "ct", "certspotter-example.com.raw.json"))
	if err != nil {
		t.Fatal(err)
	}
	certificates, err := decodeCertSpotter(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(certificates) != 13 || certificates[0].Fingerprint == "" {
		t.Fatalf("decoded %d incomplete certificates", len(certificates))
	}
	// Synthetic crt.sh shape: testdata/ct/crtsh-sample.json.
	data, err = os.ReadFile(filepath.Join("..", "..", "testdata", "ct", "crtsh-sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	certificates, err = decodeCrtSH(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(certificates) != 2 || certificates[0].Fingerprint != "" {
		t.Fatalf("decoded %#v", certificates)
	}
}

func TestFinalize(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	no := false
	input := []Certificate{
		{Fingerprint: "b", SubjectNames: []string{"b.example", "a.example", "a.example"}, NotBefore: start, NotAfter: start.Add(101 * 24 * time.Hour), Revoked: &no},
		{Fingerprint: "a", NotBefore: start.Add(time.Hour), NotAfter: start.Add(100 * 24 * time.Hour)},
		{Fingerprint: "b", NotBefore: start, NotAfter: start.Add(101 * 24 * time.Hour)},
	}
	got, truncated := Finalize(input, start, true, 1)
	if !truncated || len(got) != 1 || got[0].Fingerprint != "a" || got[0].Verdict100D != "ok" {
		t.Fatalf("Finalize() = %#v, %v", got, truncated)
	}
}

func TestSources(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Path == "/cert" {
			if request.Header.Get("Authorization") != "Bearer secret" || request.URL.Query().Get("domain") != "example.com" {
				t.Error("Cert Spotter request mismatch")
			}
			if request.URL.Query().Get("after") != "" {
				_, _ = writer.Write([]byte("[]"))
				return
			}
			_, _ = writer.Write([]byte(`[{"id":"7","cert_sha256":"aa","dns_names":["example.com"],"issuer":{"friendly_name":"CA"},"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","revoked":false}]`))
			return
		}
		_, _ = writer.Write([]byte(`[{"issuer_ca_id":1,"issuer_name":"CA","common_name":"example.com","name_value":"example.com","id":1,"not_before":"2026-01-01T00:00:00","not_after":"2026-04-01T00:00:00","serial_number":"A"}]`))
	}))
	defer server.Close()
	client := &httpx.Client{HTTP: server.Client(), UserAgent: "test", MaxAttempts: 1, Sleep: func(context.Context, time.Duration) error { return nil }}
	certificates, err := (&CertSpotter{Client: client, URL: server.URL + "/cert", APIKey: "secret"}).Search(context.Background(), Query{Domain: "example.com", IncludeSubdomains: true, Limit: 2})
	if err != nil || len(certificates) != 1 || requests != 2 {
		t.Fatalf("CertSpotter.Search = %#v, %v; requests=%d", certificates, err, requests)
	}
	certificates, err = (&CrtSH{Client: client, URL: server.URL + "/crt"}).Search(context.Background(), Query{Domain: "example.com", IncludeSubdomains: true})
	if err != nil || len(certificates) != 1 {
		t.Fatalf("CrtSH.Search = %#v, %v", certificates, err)
	}
}

func TestSourceErrors(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		kind   ErrorKind
	}{
		{name: "rate", status: 429, body: `{"error":"rate_limited"}`, kind: RateLimited},
		{name: "status", status: 500, body: "no", kind: Unavailable},
		{name: "malformed", status: 200, body: "{", kind: Malformed},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()
			client := &httpx.Client{HTTP: server.Client(), MaxAttempts: 1, Sleep: func(context.Context, time.Duration) error { return nil }}
			_, err := (&CertSpotter{Client: client, URL: server.URL}).Search(context.Background(), Query{Domain: "example.com", Limit: 1})
			if err == nil || Kind(err) != test.kind {
				t.Fatalf("error = %v, kind = %s", err, Kind(err))
			}
		})
	}
	if Kind(errors.New("plain")) != Unavailable {
		t.Fatal("plain error classification")
	}
}

func FuzzNormalizeDomain(f *testing.F) {
	f.Add("example.com")
	f.Add("*.bücher.example")
	f.Fuzz(func(_ *testing.T, value string) { _, _ = NormalizeDomain(value) })
}

func FuzzDecodeCertSpotter(f *testing.F) {
	f.Add([]byte("[]"))
	f.Fuzz(func(_ *testing.T, data []byte) { _, _ = decodeCertSpotter(data) })
}

func FuzzDecodeCrtSH(f *testing.F) {
	f.Add([]byte("[]"))
	f.Fuzz(func(_ *testing.T, data []byte) { _, _ = decodeCrtSH(data) })
}

func certspotterPage(id string, notAfter string) string {
	return `[{"id":"` + id + `","cert_sha256":"` + id + `","dns_names":["example.com"],"issuer":{"name":"CA"},"not_before":"2026-01-01T00:00:00Z","not_after":"` + notAfter + `","revoked":false}]`
}

func testClient(slept *[]time.Duration) *httpx.Client {
	return &httpx.Client{HTTP: http.DefaultClient, MaxAttempts: 1, Sleep: func(_ context.Context, d time.Duration) error {
		if slept != nil {
			*slept = append(*slept, d)
		}
		return nil
	}}
}

func TestCertSpotterPaginationGuards(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"repeated cursor": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(certspotterPage("7", "2026-04-01T00:00:00Z")))
		},
		"empty cursor": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(certspotterPage("", "2026-04-01T00:00:00Z")))
		},
		"endless": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(certspotterPage(r.URL.Query().Get("after")+"x", "2026-04-01T00:00:00Z")))
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			_, err := (&CertSpotter{Client: testClient(nil), URL: server.URL}).Search(context.Background(), Query{Domain: "example.com"})
			if Kind(err) != Malformed || err == nil {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestCertSpotterLimitCountsFinalizedRecords(t *testing.T) {
	// Pages 1 and 2 hold only expired/duplicate records; the limit must not stop before a live one.
	pages := map[string]string{
		"":  certspotterPage("1", "2026-01-15T00:00:00Z"),
		"1": certspotterPage("1", "2026-01-15T00:00:00Z"),
		"2": certspotterPage("3", "2026-06-01T00:00:00Z"),
		"3": "[]",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(pages[r.URL.Query().Get("after")]))
	}))
	defer server.Close()
	pages["1"] = `[{"id":"2","cert_sha256":"1","dns_names":["example.com"],"issuer":{"name":"CA"},"not_before":"2026-01-01T00:00:00Z","not_after":"2026-01-15T00:00:00Z","revoked":false}]`
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	result, err := (&CertSpotter{Client: testClient(nil), URL: server.URL}).Search(context.Background(), Query{Domain: "example.com", Limit: 1, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	final, _ := Finalize(result, now, false, 0)
	if len(final) != 1 || final[0].Fingerprint != "3" {
		t.Fatalf("final = %#v", final)
	}
}

func TestCertSpotterRateLimitBoundedRetry(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("Retry-After", "86400")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	var slept []time.Duration
	_, err := (&CertSpotter{Client: testClient(&slept), URL: server.URL}).Search(context.Background(), Query{Domain: "example.com"})
	if Kind(err) != RateLimited || requests != 2 || len(slept) != 1 || slept[0] != httpx.MaxRetryAfter {
		t.Fatalf("err=%v requests=%d slept=%v", err, requests, slept)
	}
}

func TestFinalizeVerdictBoundary(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	hundred := 100 * 24 * time.Hour
	for _, test := range []struct {
		name     string
		lifetime time.Duration
		days     int
		verdict  string
	}{
		{"exactly 100d", hundred, 100, "ok"},
		{"100d+1s", hundred + time.Second, 100, "exceeds"},
		{"100d-1s", hundred - time.Second, 99, "ok"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, _ := Finalize([]Certificate{{Fingerprint: "a", NotBefore: start, NotAfter: start.Add(test.lifetime)}}, start, true, 0)
			if got[0].LifetimeDays != test.days || got[0].Verdict100D != test.verdict {
				t.Fatalf("got %d %s", got[0].LifetimeDays, got[0].Verdict100D)
			}
		})
	}
}

func TestFinalizeTotalOrder(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)
	a := Certificate{DedupKey: "1:A", Issuer: "CA", Serial: "A", SubjectNames: []string{"a.example"}, NotBefore: start, NotAfter: end}
	b := Certificate{DedupKey: "1:B", Issuer: "CA", Serial: "B", SubjectNames: []string{"b.example"}, NotBefore: start, NotAfter: end}
	c := Certificate{DedupKey: "2:A", Issuer: "CA", Serial: "A", SubjectNames: []string{"a.example"}, NotBefore: start, NotAfter: end}
	for _, input := range [][]Certificate{{a, b, c}, {c, b, a}, {b, a, c}} {
		got, _ := Finalize(input, start, true, 0)
		if got[0].DedupKey != "1:A" || got[1].DedupKey != "1:B" || got[2].DedupKey != "2:A" {
			t.Fatalf("order = %s %s %s", got[0].DedupKey, got[1].DedupKey, got[2].DedupKey)
		}
	}
}

func TestDecodersRejectInvertedValidity(t *testing.T) {
	if _, err := decodeCertSpotter([]byte(certspotterPage("1", "2025-01-01T00:00:00Z"))); err == nil {
		t.Error("Cert Spotter accepted not_after before not_before")
	}
	if _, err := decodeCrtSH([]byte(`[{"issuer_ca_id":1,"issuer_name":"CA","common_name":"a","name_value":"a","not_before":"2026-01-01T00:00:00","not_after":"2025-01-01T00:00:00","serial_number":"A"}]`)); err == nil {
		t.Error("crt.sh accepted not_after before not_before")
	}
}
