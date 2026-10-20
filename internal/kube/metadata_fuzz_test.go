package kube

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// secretKeyMarker is the Secret data key of the seed corpus. It must never
// reach an error message.
const secretKeyMarker = "tls.key"

// fixedMetadataErrorTexts are the fixed error messages of the metadata
// client. Body derived content is only a leak when it appears outside of
// them.
var fixedMetadataErrorTexts = []string{
	"read metadata response: ",
	"metadata response is not decodable JSON: ",
	"metadata response exceeds ",
	"metadata response is not a PartialObjectMetadataList",
}

// jsonKind returns the kind of a JSON body and whether it decodes at all.
func jsonKind(body []byte) (string, bool) {
	var decoded struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", false
	}
	return decoded.Kind, true
}

// jsonStringValues returns every JSON string value of a body. It returns
// nothing when the body does not decode.
func jsonStringValues(body []byte) []string {
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil
	}
	values := []string{}
	var collect func(value any)
	collect = func(value any) {
		switch typed := value.(type) {
		case string:
			values = append(values, typed)
		case []any:
			for _, item := range typed {
				collect(item)
			}
		case map[string]any:
			for _, item := range typed {
				collect(item)
			}
		}
	}
	collect(decoded)
	return values
}

func FuzzRequirePartialObjectMetadataList(f *testing.F) {
	for _, seed := range []struct {
		contentType string
		status      int
		body        string
	}{
		{
			contentType: "application/json",
			status:      200,
			body:        `{"kind":"PartialObjectMetadataList","apiVersion":"meta.k8s.io/v1","metadata":{"resourceVersion":"1"},"items":[]}`,
		},
		{
			contentType: "application/json",
			status:      200,
			body: fmt.Sprintf(`{"kind":"SecretList","apiVersion":"v1","items":[{"metadata":{"name":"tls"},`+
				`"type":"Opaque","data":{%q:%q}}]}`, secretKeyMarker, keyMaterial),
		},
		{
			contentType: "application/json",
			status:      403,
			body:        `{"kind":"Status","apiVersion":"v1","status":"Failure","message":"secrets is forbidden","reason":"Forbidden","code":403}`,
		},
		{
			contentType: "application/vnd.kubernetes.protobuf;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1",
			status:      200,
			body:        "",
		},
		{
			contentType: "application/json",
			status:      200,
			body:        "",
		},
		{
			contentType: "application/json",
			status:      200,
			body:        "not json",
		},
	} {
		f.Add(seed.contentType, seed.status, []byte(seed.body))
	}
	f.Fuzz(func(t *testing.T, contentType string, status int, body []byte) {
		code := 100 + status%500
		response := &http.Response{
			StatusCode: code,
			Header:     http.Header{"Content-Type": []string{contentType}},
			Body:       io.NopCloser(bytes.NewReader(body)),
		}
		err := requirePartialObjectMetadataList(response)
		if err == nil {
			if code >= 200 && code < 300 && strings.HasPrefix(contentType, "application/json") {
				kind, ok := jsonKind(body)
				if !ok {
					t.Fatalf("accepted a body that is not decodable JSON")
				}
				if kind != "PartialObjectMetadataList" {
					t.Fatalf("accepted a %q body as a PartialObjectMetadataList", kind)
				}
			}
			remaining, readErr := io.ReadAll(response.Body)
			if readErr != nil {
				t.Fatalf("read the body of an accepted response: %v", readErr)
			}
			if !bytes.Equal(remaining, body) {
				t.Fatalf("the body of an accepted response changed: %d bytes read, %d expected", len(remaining), len(body))
			}
			return
		}
		text := err.Error()
		if strings.Contains(text, keyMaterial) {
			t.Fatalf("the error leaked the secret key material: %v", err)
		}
		if strings.Contains(text, secretKeyMarker) {
			t.Fatalf("the error leaked the secret key name: %v", err)
		}
		residual := text
		for _, fixed := range fixedMetadataErrorTexts {
			residual = strings.ReplaceAll(residual, fixed, "")
		}
		for _, value := range jsonStringValues(body) {
			if len(value) > 8 && strings.Contains(residual, value) {
				t.Fatalf("the error leaked a JSON string value of the body: %v", err)
			}
		}
	})
}
