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

// CrtSH searches the crt.sh JSON endpoint.
type CrtSH struct {
	Client *httpx.Client
	URL    string
}

// Name returns the stable source identifier.
func (s *CrtSH) Name() string { return "crtsh" }

// Search returns normalized crt.sh records.
func (s *CrtSH) Search(ctx context.Context, query Query) ([]Certificate, error) {
	term := query.Domain
	if query.IncludeSubdomains {
		term = "%." + term
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint(s.URL, url.Values{"q": {term}, "output": {"json"}}), nil)
	if err != nil {
		return nil, malformed(s.Name(), err)
	}
	status, _, body, err := s.Client.Do(ctx, request)
	if err != nil {
		if errors.Is(err, httpx.ErrBodyTooLarge) {
			return nil, malformed(s.Name(), fmt.Errorf("oversized crtsh response: %w", err))
		}
		return nil, unavailable(s.Name(), err)
	}
	if status < 200 || status >= 300 {
		return nil, unavailable(s.Name(), fmt.Errorf("HTTP status %d", status))
	}
	result, err := decodeCrtSH(body)
	if err != nil {
		return nil, malformed(s.Name(), err)
	}
	return result, nil
}

// SearchResult returns normalized crt.sh records and reports whether the
// query stopped before the source was exhausted.
func (s *CrtSH) SearchResult(ctx context.Context, query Query) (Result, error) {
	certificates, err := s.Search(ctx, query)
	if err != nil {
		return Result{}, err
	}
	entryCap := query.Limit
	if entryCap < MaxEntries {
		entryCap = MaxEntries
	}
	if len(certificates) > entryCap {
		return Result{Certificates: certificates[:entryCap], Truncated: true}, nil
	}
	return Result{Certificates: certificates}, nil
}

type crtSHRecord struct {
	IssuerCAID int64  `json:"issuer_ca_id"`
	IssuerName string `json:"issuer_name"`
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
	ID         int64  `json:"id"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	Serial     string `json:"serial_number"`
}

func decodeCrtSH(data []byte) ([]Certificate, error) {
	var records []crtSHRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	result := make([]Certificate, 0, len(records))
	for _, record := range records {
		notBefore, err := parseCrtSHTime(record.NotBefore)
		if err != nil {
			return nil, fmt.Errorf("not_before: %w", err)
		}
		notAfter, err := parseCrtSHTime(record.NotAfter)
		if err != nil {
			return nil, fmt.Errorf("not_after: %w", err)
		}
		if notAfter.Before(notBefore) {
			return nil, errors.New("not_after precedes not_before")
		}
		names := strings.Split(record.NameValue, "\n")
		if record.CommonName != "" {
			names = append(names, record.CommonName)
		}
		result = append(result, Certificate{Serial: record.Serial, SubjectNames: names, Issuer: record.IssuerName, NotBefore: notBefore, NotAfter: notAfter, Source: "crtsh", DedupKey: strconv.FormatInt(record.IssuerCAID, 10) + ":" + record.Serial})
	}
	return result, nil
}

func parseCrtSHTime(value string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02T15:04:05", time.RFC3339} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, errors.New("unsupported timestamp")
}
