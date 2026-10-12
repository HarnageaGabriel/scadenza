package ct

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/httpx"
)

// CertSpotter searches the Cert Spotter issuance API.
type CertSpotter struct {
	Client *httpx.Client
	URL    string
	APIKey string
}

// Name returns the stable source identifier.
func (s *CertSpotter) Name() string { return "certspotter" }

// MaxPages bounds Cert Spotter pagination.
const MaxPages = 1000

// Search returns normalized Cert Spotter issuances.
func (s *CertSpotter) Search(ctx context.Context, query Query) ([]Certificate, error) {
	var result []Certificate
	after := ""
	for pages := 0; ; pages++ {
		if pages >= MaxPages {
			return nil, malformed(s.Name(), errors.New("page limit exceeded"))
		}
		body, err := s.fetch(ctx, query, after)
		if err != nil {
			return nil, err
		}
		page, err := decodeCertSpotter(body)
		if err != nil {
			return nil, malformed(s.Name(), err)
		}
		if len(page) == 0 {
			return result, nil
		}
		next := page[len(page)-1].DedupKey
		if next == "" || next == after {
			return nil, malformed(s.Name(), errors.New("pagination cursor missing or not advancing"))
		}
		after = next
		result = append(result, page...)
		if query.Limit > 0 {
			if kept, _ := Finalize(result, query.Now, query.IncludeExpired, 0); len(kept) >= query.Limit {
				return result, nil
			}
		}
	}
}

// maxRateLimitRetries is the number of bounded retries after a 429.
const maxRateLimitRetries = 1

func (s *CertSpotter) fetch(ctx context.Context, query Query, after string) ([]byte, error) {
	parameters := url.Values{"domain": {query.Domain}, "include_subdomains": {strconv.FormatBool(query.IncludeSubdomains)}, "match_wildcards": {"true"}, "expand": {"dns_names", "issuer"}}
	if after != "" {
		parameters.Set("after", after)
	}
	for retry := 0; ; retry++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint(s.URL, parameters), nil)
		if err != nil {
			return nil, malformed(s.Name(), err)
		}
		if s.APIKey != "" {
			request.Header.Set("Authorization", "Bearer "+s.APIKey)
		}
		status, headers, body, err := s.Client.Do(ctx, request)
		if err != nil {
			if errors.Is(err, httpx.ErrBodyTooLarge) {
				return nil, malformed(s.Name(), err)
			}
			return nil, unavailable(s.Name(), err)
		}
		if status != http.StatusTooManyRequests && !bytesContainRateLimited(body) {
			if status < 200 || status >= 300 {
				return nil, unavailable(s.Name(), fmt.Errorf("HTTP status %d", status))
			}
			return body, nil
		}
		if retry >= maxRateLimitRetries {
			return nil, &SourceError{Kind: RateLimited, Source: s.Name(), Err: errors.New("request quota reached")}
		}
		if delay := s.Client.RetryDelay(headers); delay > 0 {
			if err := s.Client.Sleep(ctx, delay); err != nil {
				return nil, unavailable(s.Name(), err)
			}
		}
	}
}

type certSpotterRecord struct {
	ID          string   `json:"id"`
	Fingerprint string   `json:"cert_sha256"`
	DNSNames    []string `json:"dns_names"`
	Issuer      struct {
		FriendlyName string `json:"friendly_name"`
		Name         string `json:"name"`
	} `json:"issuer"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	Revoked   bool   `json:"revoked"`
}

func decodeCertSpotter(data []byte) ([]Certificate, error) {
	var records []certSpotterRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	result := make([]Certificate, 0, len(records))
	for _, record := range records {
		notBefore, err := time.Parse(time.RFC3339, record.NotBefore)
		if err != nil {
			return nil, fmt.Errorf("not_before: %w", err)
		}
		notAfter, err := time.Parse(time.RFC3339, record.NotAfter)
		if err != nil {
			return nil, fmt.Errorf("not_after: %w", err)
		}
		if notAfter.Before(notBefore) {
			return nil, errors.New("not_after precedes not_before")
		}
		issuer := record.Issuer.Name
		if record.Issuer.FriendlyName != "" && record.Issuer.FriendlyName != issuer {
			if issuer == "" {
				issuer = record.Issuer.FriendlyName
			} else {
				issuer += " (" + record.Issuer.FriendlyName + ")"
			}
		}
		revoked := record.Revoked
		result = append(result, Certificate{Fingerprint: strings.ToLower(record.Fingerprint), SubjectNames: record.DNSNames, Issuer: issuer, NotBefore: notBefore, NotAfter: notAfter, Revoked: &revoked, Source: "certspotter", DedupKey: record.ID})
	}
	return result, nil
}

func bytesContainRateLimited(data []byte) bool {
	return strings.Contains(string(data), `"rate_limited"`)
}

func unavailable(source string, err error) error {
	return &SourceError{Kind: Unavailable, Source: source, Err: err}
}

func malformed(source string, err error) error {
	return &SourceError{Kind: Malformed, Source: source, Err: err}
}
