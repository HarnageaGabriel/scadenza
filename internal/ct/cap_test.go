package ct

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/HarnageaGabriel/scadenza/internal/httpx"
)

var (
	_ Source           = (*CertSpotter)(nil)
	_ Source           = (*CrtSH)(nil)
	_ TruncatingSource = (*CertSpotter)(nil)
	_ TruncatingSource = (*CrtSH)(nil)
)

// certspotterPageIDs builds a Cert Spotter page from explicit record IDs.
func certspotterPageIDs(ids ...string) string {
	records := make([]string, 0, len(ids))
	for _, id := range ids {
		records = append(records, `{"id":"`+id+`","cert_sha256":"`+id+`","dns_names":["example.com"],"issuer":{"name":"CA"},`+
			`"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","revoked":false}`)
	}
	return "[" + strings.Join(records, ",") + "]"
}

// certspotterPageOf builds a Cert Spotter page with count distinct records.
func certspotterPageOf(prefix string, count int) string {
	ids := make([]string, 0, count)
	for index := 0; index < count; index++ {
		ids = append(ids, prefix+strconv.Itoa(index))
	}
	return certspotterPageIDs(ids...)
}

func TestCertSpotterStopsAtEntryCap(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = writer.Write([]byte(certspotterPageOf("page-"+strconv.Itoa(requests)+"-", 1000)))
	}))
	defer server.Close()
	result, err := (&CertSpotter{Client: testClient(nil), URL: server.URL}).SearchResult(context.Background(), Query{Domain: "example.com"})
	if err != nil {
		t.Fatalf("SearchResult() error = %v", err)
	}
	if !result.Truncated {
		t.Fatal("SearchResult() did not report truncation")
	}
	if len(result.Certificates) != MaxEntries {
		t.Fatalf("collected %d certificates, want %d", len(result.Certificates), MaxEntries)
	}
	if requests != MaxEntries/1000 {
		t.Fatalf("requests = %d, want %d", requests, MaxEntries/1000)
	}
}

func TestCertSpotterStopsOnRepeatedCursor(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = writer.Write([]byte(certspotterPage("7", "2026-04-01T00:00:00Z")))
	}))
	defer server.Close()
	result, err := (&CertSpotter{Client: testClient(nil), URL: server.URL}).SearchResult(context.Background(), Query{Domain: "example.com"})
	if err == nil || Kind(err) != Malformed {
		t.Fatalf("error = %v, kind = %s", err, Kind(err))
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
	if len(result.Certificates) != 1 {
		t.Fatalf("collected %d certificates, want 1", len(result.Certificates))
	}
}

func TestCertSpotterStopsOnEmptyPage(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = writer.Write([]byte("[]"))
	}))
	defer server.Close()
	result, err := (&CertSpotter{Client: testClient(nil), URL: server.URL}).SearchResult(context.Background(), Query{Domain: "example.com"})
	if err != nil {
		t.Fatalf("SearchResult() error = %v", err)
	}
	if result.Truncated || len(result.Certificates) != 0 || requests != 1 {
		t.Fatalf("result = %#v requests = %d", result, requests)
	}
}

func TestCertSpotterStopsOnPageWithoutNewRecords(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 1 {
			_, _ = writer.Write([]byte(certspotterPageIDs("a-0", "a-1")))
			return
		}
		// The cursor advances but every record was already collected.
		_, _ = writer.Write([]byte(certspotterPageIDs("a-1", "a-0")))
	}))
	defer server.Close()
	result, err := (&CertSpotter{Client: testClient(nil), URL: server.URL}).SearchResult(context.Background(), Query{Domain: "example.com"})
	if err != nil {
		t.Fatalf("SearchResult() error = %v", err)
	}
	if result.Truncated || len(result.Certificates) != 2 || requests != 2 {
		t.Fatalf("result = %#v requests = %d", result, requests)
	}
}

func TestCertSpotterExplicitLimitWinsOverCap(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = writer.Write([]byte(certspotterPageOf("p-"+strconv.Itoa(requests)+"-", 10)))
	}))
	defer server.Close()
	result, err := (&CertSpotter{Client: testClient(nil), URL: server.URL}).SearchResult(context.Background(), Query{Domain: "example.com", Limit: 5})
	if err != nil {
		t.Fatalf("SearchResult() error = %v", err)
	}
	if !result.Truncated {
		t.Fatal("explicit limit did not report truncation")
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}
	if len(result.Certificates) != 10 {
		t.Fatalf("collected %d certificates, want 10", len(result.Certificates))
	}
}

func TestCrtSHResultIsNotTruncatedForSmallResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`[{"issuer_ca_id":1,"issuer_name":"CA","common_name":"example.com","name_value":"example.com","id":1,"not_before":"2026-01-01T00:00:00","not_after":"2026-04-01T00:00:00","serial_number":"A"}]`))
	}))
	defer server.Close()
	result, err := (&CrtSH{Client: testClient(nil), URL: server.URL}).SearchResult(context.Background(), Query{Domain: "example.com"})
	if err != nil {
		t.Fatalf("SearchResult() error = %v", err)
	}
	if result.Truncated || len(result.Certificates) != 1 {
		t.Fatalf("result = %#v", result)
	}
}

func TestCrtSHOversizedResponseIsIdentifiable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		chunk := make([]byte, 1<<20)
		for written := int64(0); written <= httpx.MaxBodyBytes; written += int64(len(chunk)) {
			if _, err := writer.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	_, err := (&CrtSH{Client: testClient(nil), URL: server.URL}).Search(context.Background(), Query{Domain: "example.com"})
	if !errors.Is(err, httpx.ErrBodyTooLarge) {
		t.Fatalf("error = %v, want %v", err, httpx.ErrBodyTooLarge)
	}
	if Kind(err) != Malformed {
		t.Fatalf("kind = %s, want %s", Kind(err), Malformed)
	}
}
