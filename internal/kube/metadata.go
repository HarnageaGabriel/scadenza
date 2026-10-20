package kube

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// maxMetadataResponseBytes bounds how much of a metadata response is buffered
// for inspection. Real PartialObjectMetadataList pages are far smaller.
const maxMetadataResponseBytes = 32 << 20

// partialObjectMetadataContentTypes are the only media types the metadata
// client may negotiate: the two PartialObjectMetadataList variants, never the
// bare application/json fallback. With the fallback a server or proxy that
// ignores the as= parameter can answer with full Secret objects, including
// Secret data, even though Secret data reads were not requested.
const partialObjectMetadataContentTypes = "application/vnd.kubernetes.protobuf;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1,application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1"

// partialObjectMetadataTransport enforces the metadata-only contract at the
// HTTP layer. client-go's metadata client hardcodes an Accept header that ends
// with a bare application/json fallback and its constructors reset
// AcceptContentTypes, so the header is rewritten here as well as in the config.
// It also refuses any successful JSON response that is not a
// PartialObjectMetadataList, so a server that ignores the as= parameter cannot
// smuggle full Secret objects (including Secret data) into the scan.
func partialObjectMetadataTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &partialMetadataRoundTripper{base: base}
}

type partialMetadataRoundTripper struct {
	base http.RoundTripper
}

func (t *partialMetadataRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header.Set("Accept", dropBareJSON(request.Header.Get("Accept")))
	response, err := t.base.RoundTrip(clone)
	if err != nil {
		return nil, err
	}
	if err := requirePartialObjectMetadataList(response); err != nil {
		_ = response.Body.Close()
		return nil, err
	}
	return response, nil
}

// dropBareJSON removes the bare application/json entry from an Accept header,
// keeping the PartialObjectMetadata variants. An empty result keeps the
// original header so the request is never left without Accept.
func dropBareJSON(accept string) string {
	parts := strings.Split(accept, ",")
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" || strings.EqualFold(trimmed, "application/json") {
			continue
		}
		kept = append(kept, trimmed)
	}
	if len(kept) == 0 {
		return accept
	}
	return strings.Join(kept, ",")
}

// requirePartialObjectMetadataList rejects a JSON response that is not a
// PartialObjectMetadataList. Error responses keep their API status so the
// caller can classify them (forbidden, unauthorized, and so on); protobuf and
// other media types are decoded and type-checked by client-go. The error never
// includes the response body.
func requirePartialObjectMetadataList(response *http.Response) error {
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil
	}
	if !strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxMetadataResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read metadata response: %w", err)
	}
	if len(body) > maxMetadataResponseBytes {
		return fmt.Errorf("metadata response exceeds %d bytes", maxMetadataResponseBytes)
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	var decoded struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return fmt.Errorf("metadata response is not decodable JSON: %w", err)
	}
	if decoded.Kind != "PartialObjectMetadataList" {
		return fmt.Errorf("metadata response is not a PartialObjectMetadataList")
	}
	return nil
}
