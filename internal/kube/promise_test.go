package kube

import (
	"context"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// TestScanCRDMissingNotFoundIsInformational pins the promise that a
// cert-manager list answered with a NotFound API error means the custom
// resource definitions are not installed: the scan reports the informational
// SCD-0018 problem, returns no error, and still reports the TLS Secret it
// read. See docs/diagnostics/SCD-0018.md and docs/adr/0005-kubernetes-client.md
// ("A missing cert-manager installation is expected ... as an informational
// diagnostic (SCD-0018), not an error, and TLS Secrets are still reported").
func TestScanCRDMissingNotFoundIsInformational(t *testing.T) {
	_, chain, _ := generateChain(t)
	secret := tlsSecret("payments", "db", map[string][]byte{"tls.crt": chain}, nil)
	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(schemeWithCertManager(), map[schema.GroupVersionResource]string{})
	dynamicClient.PrependReactor("list", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(
			schema.GroupResource{Group: CertManagerGroup, Resource: "certificates"},
			"certificates.cert-manager.io",
		)
	})
	scanner := New(Clients{Kubernetes: k8sfake.NewSimpleClientset(secret), Dynamic: dynamicClient}, testOptions(t, ""))

	result, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, problem := range result.Problems {
		if problem.Code == CodeUnreachable {
			t.Fatalf("a missing CRD was reported as unreachable: %+v", problem)
		}
	}
	if len(result.Problems) != 1 {
		t.Fatalf("problems = %+v", result.Problems)
	}
	problem := result.Problems[0]
	if problem.Code != CodeCRDMissing {
		t.Fatalf("problem code = %q, want %q", problem.Code, CodeCRDMissing)
	}
	if problem.HTTPStatus != 404 || problem.Reason != metav1.StatusReasonNotFound {
		t.Fatalf("problem = %+v", problem)
	}
	if len(result.Certificates) != 1 {
		t.Fatalf("certificates = %+v", result.Certificates)
	}
	if result.Certificates[0].Observations[0].Source != SourceSecret {
		t.Fatalf("observation = %+v", result.Certificates[0].Observations[0])
	}
}

// TestScanCertManagerIssuerRefWithoutKindUsesIssuerDefault pins the promise
// that a cert-manager Certificate whose spec.issuerRef carries a name but no
// kind is reported with the cert-manager default kind Issuer and the issuer
// text "Issuer/<name>". The kind also drives the issuer lookup, so the issuer
// type is still resolved. See docs/cli/scan.md ("reports the issuer kind and
// name") and the cert-manager default for spec.issuerRef.kind.
func TestScanCertManagerIssuerRefWithoutKindUsesIssuerDefault(t *testing.T) {
	certificate := certificateObject("payments", "api", map[string]any{
		"secretName": "api-tls",
		"dnsNames":   []any{"api.example.com"},
		"issuerRef":  map[string]any{"name": "production"},
	}, map[string]any{
		"notAfter": "2026-04-01T00:00:00Z",
	})
	issuer := issuerObject(issuerResourceName, "payments", "production", map[string]any{
		"acme": map[string]any{"server": "https://acme.example.com/dir"},
	})
	scanner := scannerWith(t, testOptions(t, ""), nil, []*unstructured.Unstructured{certificate, issuer}, certManagerListKinds())

	result, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(result.Certificates) != 1 {
		t.Fatalf("certificates = %+v", result.Certificates)
	}
	got := result.Certificates[0]
	if got.Issuer != "Issuer/production" {
		t.Fatalf("issuer = %q, want %q", got.Issuer, "Issuer/production")
	}
	facts := got.Observations[0].Kubernetes
	if facts == nil {
		t.Fatalf("observation = %+v", got.Observations[0])
	}
	if facts.IssuerKind != IssuerKind || facts.IssuerName != "production" {
		t.Fatalf("issuer kind and name = %q/%q, want %q/production", facts.IssuerKind, facts.IssuerName, IssuerKind)
	}
	if facts.IssuerType != IssuerTypeACME {
		t.Fatalf("issuer type = %q, want %q", facts.IssuerType, IssuerTypeACME)
	}
	if detail := got.Observations[0].Detail; !strings.Contains(detail, "issuer Issuer/production") {
		t.Fatalf("observation detail = %q", detail)
	}
}

// TestScanEmptyNamespaceOptionScansAllNamespaces pins the promise that a
// namespace option whose entries are all empty lists every namespace instead
// of nothing: the scan must not read zero namespaces. The CLI passes the
// --namespace values through unchanged, so `--namespace ""` produces exactly
// this list, and the SCD-0029 detail already reports "all" for it. See
// docs/cli/scan.md ("--namespace ns (repeatable, default all namespaces)").
func TestScanEmptyNamespaceOptionScansAllNamespaces(t *testing.T) {
	_, chain, _ := generateChain(t)
	secrets := []runtime.Object{
		tlsSecret("payments", "a", map[string][]byte{"tls.crt": chain}, nil),
		tlsSecret("other", "b", map[string][]byte{"tls.crt": chain}, nil),
	}
	tests := []struct {
		name       string
		namespaces []string
	}{
		{"empty namespace", []string{""}},
		{"blank namespace", []string{"  "}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := testOptions(t, "")
			options.Namespaces = test.namespaces
			scanner := scannerWith(t, options, secrets, nil, certManagerListKinds())
			if scope := scanner.scope(); len(scope) != 1 || scope[0] != metav1.NamespaceAll {
				t.Fatalf("scope = %v, want every namespace", scope)
			}
			result, err := scanner.Scan(context.Background())
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if len(result.Certificates) != 2 {
				t.Fatalf("certificates = %+v", result.Certificates)
			}
		})
	}
}
