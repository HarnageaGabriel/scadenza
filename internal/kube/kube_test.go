package kube

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/clock"
	"github.com/HarnageaGabriel/scadenza/internal/owner"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	metadatafake "k8s.io/client-go/metadata/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/klog/v2"
)

const keyMaterial = "SUPERSECRETKEYMATERIAL"

var testNow = time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

// generateCertificate returns a self-signed CA-style certificate.
func generateCertificate(t *testing.T, commonName string, dnsNames []string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 96))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             testNow.Add(-24 * time.Hour),
		NotAfter:              testNow.Add(90 * 24 * time.Hour),
		DNSNames:              dnsNames,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// generateChain returns a leaf signed by a CA, plus the CA certificate.
func generateChain(t *testing.T) (*x509.Certificate, []byte, *x509.Certificate) {
	t.Helper()
	ca := generateCertificate(t, "Scadenza Test CA", nil)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Re-issue the CA with a key we keep, so the leaf can be signed by it.
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 96))
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               ca.Subject,
		NotBefore:             testNow.Add(-24 * time.Hour),
		NotAfter:              testNow.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 96))
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "db.payments.svc"},
		NotBefore:    testNow.Add(-24 * time.Hour),
		NotAfter:     testNow.Add(60 * 24 * time.Hour),
		DNSNames:     []string{"db.payments.svc", "db.payments.svc.cluster.local"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	return leaf, chain, caCert
}

func tlsSecret(namespace, name string, data map[string][]byte, labels map[string]string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels},
		Type:       corev1.SecretTypeTLS,
		Data:       data,
	}
}

func metadataFor(t *testing.T, secrets ...*corev1.Secret) *metadatafake.FakeMetadataClient {
	t.Helper()
	scheme := metadatafake.NewTestScheme()
	if err := metav1.AddMetaToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	objects := make([]runtime.Object, 0, len(secrets))
	for _, secret := range secrets {
		objects = append(objects, &metav1.PartialObjectMetadata{
			TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
			ObjectMeta: secret.ObjectMeta,
		})
	}
	return metadatafake.NewSimpleMetadataClient(scheme, objects...)
}

func certManagerListKinds() map[schema.GroupVersionResource]string {
	return map[schema.GroupVersionResource]string{
		certManagerResource(certificateResourceName): "CertificateList",
		certManagerResource(issuerResourceName):      "IssuerList",
		certManagerResource(clusterIssuerResource):   "ClusterIssuerList",
	}
}

func schemeWithCertManager() *runtime.Scheme {
	scheme := runtime.NewScheme()
	for _, kind := range []string{"Certificate", "Issuer", "ClusterIssuer"} {
		gvk := schema.GroupVersionKind{Group: CertManagerGroup, Version: CertManagerVersion, Kind: kind}
		scheme.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})
		scheme.AddKnownTypeWithName(gvk.GroupVersion().WithKind(kind+"List"), &unstructured.UnstructuredList{})
	}
	return scheme
}

func scannerWith(t *testing.T, options Options, core []runtime.Object, dynamic []*unstructured.Unstructured, listKinds map[schema.GroupVersionResource]string) *Scanner {
	t.Helper()
	objects := make([]runtime.Object, 0, len(dynamic))
	for _, object := range dynamic {
		objects = append(objects, object)
	}
	return New(Clients{
		Kubernetes: k8sfake.NewSimpleClientset(core...),
		Dynamic:    dynamicfake.NewSimpleDynamicClientWithCustomListKinds(schemeWithCertManager(), listKinds, objects...),
	}, options)
}

func testOptions(t *testing.T, document string) Options {
	t.Helper()
	config, err := owner.ParseConfig([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	return Options{Owners: config, Clock: clock.Fixed{Time: testNow}, Secrets: true}
}

func TestScanTLSSecret(t *testing.T) {
	leaf, chain, _ := generateChain(t)
	secret := tlsSecret("payments", "db-tls", map[string][]byte{
		"tls.crt": chain,
		"tls.key": []byte("-----BEGIN PRIVATE KEY-----\n" + keyMaterial + "\n-----END PRIVATE KEY-----\n"),
	}, map[string]string{"scadenza.io/owner": "team-pay"})
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "payments", Labels: map[string]string{"scadenza.io/owner": "team-ns"}}}
	scanner := scannerWith(t, testOptions(t, ""), []runtime.Object{secret, namespace}, nil, certManagerListKinds())

	result, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(result.Certificates) != 1 {
		t.Fatalf("certificates = %v", result.Certificates)
	}
	certificate := result.Certificates[0]
	sum := sha256.Sum256(leaf.Raw)
	if certificate.Fingerprint != hex.EncodeToString(sum[:]) {
		t.Fatalf("fingerprint = %q", certificate.Fingerprint)
	}
	if certificate.Serial != strings.ToLower(leaf.SerialNumber.Text(16)) {
		t.Fatalf("serial = %q", certificate.Serial)
	}
	if len(certificate.Names) != 2 || certificate.Names[0] != "db.payments.svc" {
		t.Fatalf("names = %v", certificate.Names)
	}
	if certificate.Public != nil {
		t.Fatalf("public = %v; a private chain must stay unknown", *certificate.Public)
	}
	if diff := len(certificate.Owners); diff != 2 {
		t.Fatalf("owners = %v", certificate.Owners)
	}
	if certificate.Observations[0].Source != SourceSecret || certificate.Observations[0].Kubernetes == nil {
		t.Fatalf("observation = %+v", certificate.Observations[0])
	}
	if len(result.Problems) != 0 {
		t.Fatalf("problems = %v", result.Problems)
	}
}

func TestScanReadsSecretMetadataOnlyByDefault(t *testing.T) {
	secret := tlsSecret("payments", "db-tls", map[string][]byte{
		"tls.crt": []byte("certificate-data-not-allowed"),
		"tls.key": []byte(keyMaterial),
	}, map[string]string{"scadenza.io/owner": "team-pay"})
	secret.Annotations = map[string]string{certificateNameAnnotation: "db"}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "payments"}}
	owners, ownerErr := owner.ParseConfig(nil)
	if ownerErr != nil {
		t.Fatal(ownerErr)
	}
	typedClient := k8sfake.NewSimpleClientset(secret, namespace)
	listedSecrets := false
	typedClient.PrependReactor("list", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		listedSecrets = true
		return true, nil, errors.New("Secret data must not be listed")
	})
	scanner := New(Clients{
		Kubernetes: typedClient,
		Metadata:   metadataFor(t, secret),
		Dynamic: dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
			schemeWithCertManager(), certManagerListKinds(),
		),
	}, Options{Clock: clock.Fixed{Time: testNow}, Owners: owners})

	result, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if listedSecrets {
		t.Fatal("default scan listed full Secrets")
	}
	if len(result.Certificates) != 1 {
		t.Fatalf("certificates = %+v", result.Certificates)
	}
	certificate := result.Certificates[0]
	if certificate.Fingerprint != "" || certificate.Serial != "" || len(certificate.Names) != 0 ||
		!certificate.NotBefore.IsZero() || !certificate.NotAfter.IsZero() || certificate.Public != nil {
		t.Fatalf("metadata-only entry contains certificate data: %+v", certificate)
	}
	if len(certificate.Observations) != 1 {
		t.Fatalf("observations = %+v", certificate.Observations)
	}
	observation := certificate.Observations[0]
	if observation.Source != SourceSecretMetadata || observation.Location != "payments/db-tls" ||
		observation.Kubernetes == nil || observation.Kubernetes.Name != "db-tls" ||
		observation.Kubernetes.Namespace != "payments" ||
		observation.Kubernetes.CertificateName != "db" {
		t.Fatalf("metadata observation = %+v", observation)
	}
	if len(certificate.Owners) != 1 || certificate.Owners[0].Value != "team-pay" {
		t.Fatalf("owners = %+v", certificate.Owners)
	}
	encoded, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if strings.Contains(string(encoded), keyMaterial) || strings.Contains(string(encoded), "certificate-data-not-allowed") {
		t.Fatalf("Secret data leaked: %s", encoded)
	}
}

func TestScanBuildsCertificateFromCertManagerStatusByDefault(t *testing.T) {
	certificate := certificateObject("payments", "api", map[string]any{
		"secretName":  "api-tls",
		"dnsNames":    []any{"api.example.com", "www.example.com"},
		"duration":    "2160h",
		"renewBefore": "720h",
		"issuerRef":   map[string]any{"name": "production", "kind": ClusterIssuerKind},
	}, map[string]any{
		"notBefore":   "2026-01-01T00:00:00Z",
		"notAfter":    "2026-04-01T00:00:00Z",
		"renewalTime": "2026-03-01T00:00:00Z",
		"conditions":  []any{map[string]any{"type": "Ready", "status": "True", "reason": "Ready"}},
	})
	owners, err := owner.ParseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	scanner := New(Clients{
		Kubernetes: k8sfake.NewSimpleClientset(),
		Metadata:   metadataFor(t),
		Dynamic: dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
			schemeWithCertManager(), certManagerListKinds(), certificate,
		),
	}, Options{Clock: clock.Fixed{Time: testNow}, Owners: owners})

	result, scanErr := scanner.Scan(context.Background())
	if scanErr != nil {
		t.Fatalf("Scan: %v", scanErr)
	}
	if len(result.Certificates) != 1 {
		t.Fatalf("certificates = %+v", result.Certificates)
	}
	got := result.Certificates[0]
	if got.Fingerprint != "" || got.DedupKey != "cert-manager/payments/api" ||
		!slices.Equal(got.Names, []string{"api.example.com", "www.example.com"}) ||
		got.NotBefore.Format(time.RFC3339) != "2026-01-01T00:00:00Z" ||
		got.NotAfter.Format(time.RFC3339) != "2026-04-01T00:00:00Z" {
		t.Fatalf("status certificate = %+v", got)
	}
	facts := got.Observations[0].Kubernetes
	if facts == nil || facts.NotBefore != "2026-01-01T00:00:00Z" || facts.NotAfter != "2026-04-01T00:00:00Z" {
		t.Fatalf("status facts = %+v", facts)
	}
}

func TestScanContinuesWhenSecretMetadataIsForbidden(t *testing.T) {
	metadataClient := metadataFor(t)
	metadataClient.PrependReactor("list", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "", errors.New("denied"))
	})
	scanner := New(Clients{
		Kubernetes: k8sfake.NewSimpleClientset(),
		Metadata:   metadataClient,
		Dynamic: dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
			schemeWithCertManager(), certManagerListKinds(),
		),
	}, Options{})

	result, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(result.Problems) != 1 || result.Problems[0].Code != CodeForbidden || result.Problems[0].Resource != "secrets" {
		t.Fatalf("problems = %+v", result.Problems)
	}
}

func TestScanNeverExposesPrivateKey(t *testing.T) {
	_, chain, _ := generateChain(t)
	key := []byte("-----BEGIN PRIVATE KEY-----\n" + keyMaterial + "\n-----END PRIVATE KEY-----\n")
	secrets := []runtime.Object{
		tlsSecret("payments", "good", map[string][]byte{"tls.crt": chain, "tls.key": key}, nil),
		tlsSecret("payments", "malformed", map[string][]byte{"tls.crt": []byte("-----BEGIN CERTIFICATE-----\n" + keyMaterial + "\n-----END CERTIFICATE-----\n"), "tls.key": key}, nil),
		tlsSecret("payments", "missing", map[string][]byte{"tls.key": key}, nil),
	}
	scanner := scannerWith(t, testOptions(t, ""), secrets, nil, certManagerListKinds())
	result, err := scanner.Scan(context.Background())
	if err == nil {
		if rendered, marshalErr := json.Marshal(result); marshalErr == nil && strings.Contains(string(rendered), keyMaterial) {
			t.Fatalf("key material appeared in scan output: %s", rendered)
		}
	}
	for _, problem := range result.Problems {
		if strings.Contains(problem.Detail, keyMaterial) {
			t.Fatalf("key material appeared in problem detail: %+v", problem)
		}
	}
	if err != nil && strings.Contains(err.Error(), keyMaterial) {
		t.Fatalf("key material appeared in error: %v", err)
	}
	if len(result.Problems) != 2 {
		t.Fatalf("problems = %+v", result.Problems)
	}
	for _, problem := range result.Problems {
		if problem.Code != CodeCertificateParseFailed && problem.Code != CodeSecretWithoutCertificate {
			t.Fatalf("unexpected problem %+v", problem)
		}
	}
}

func TestScanSecretProblems(t *testing.T) {
	_, chain, _ := generateChain(t)
	tests := []struct {
		name   string
		secret *corev1.Secret
		code   string
	}{
		{"missing tls.crt", tlsSecret("payments", "a", map[string][]byte{"tls.key": []byte("x")}, nil), CodeSecretWithoutCertificate},
		{"empty tls.crt", tlsSecret("payments", "b", map[string][]byte{"tls.crt": []byte("   ")}, nil), CodeSecretWithoutCertificate},
		{"garbage tls.crt", tlsSecret("payments", "c", map[string][]byte{"tls.crt": []byte("not a pem chain")}, nil), CodeCertificateParseFailed},
		{"valid tls.crt", tlsSecret("payments", "d", map[string][]byte{"tls.crt": chain}, nil), ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scanner := scannerWith(t, testOptions(t, ""), []runtime.Object{test.secret}, nil, certManagerListKinds())
			result, err := scanner.Scan(context.Background())
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if test.code == "" {
				if len(result.Problems) != 0 || len(result.Certificates) != 1 {
					t.Fatalf("problems=%v certificates=%v", result.Problems, result.Certificates)
				}
				return
			}
			if len(result.Problems) != 1 || result.Problems[0].Code != test.code {
				t.Fatalf("problems = %+v", result.Problems)
			}
		})
	}
}

func TestScanIgnoresNonTLSSecrets(t *testing.T) {
	opaque := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "payments"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"tls.crt": []byte("not used")},
	}
	scanner := scannerWith(t, testOptions(t, ""), []runtime.Object{opaque}, nil, certManagerListKinds())
	result, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(result.Certificates) != 0 || len(result.Problems) != 0 {
		t.Fatalf("certificates=%v problems=%v", result.Certificates, result.Problems)
	}
}

func TestScanPublicOnlyWhenVerified(t *testing.T) {
	_, chain, ca := generateChain(t)
	secret := tlsSecret("payments", "db", map[string][]byte{"tls.crt": chain}, nil)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	options := testOptions(t, "")
	options.Roots = roots
	scanner := scannerWith(t, options, []runtime.Object{secret}, nil, certManagerListKinds())
	result, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(result.Certificates) != 1 || result.Certificates[0].Public == nil || !*result.Certificates[0].Public {
		t.Fatalf("public = %+v", result.Certificates)
	}
}

func certificateObject(namespace, name string, spec, status map[string]any) *unstructured.Unstructured {
	object := map[string]any{
		"apiVersion": CertManagerGroup + "/" + CertManagerVersion,
		"kind":       "Certificate",
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"spec":       spec,
	}
	if status != nil {
		object["status"] = status
	}
	return &unstructured.Unstructured{Object: object}
}

func issuerObject(resource, namespace, name string, spec map[string]any) *unstructured.Unstructured {
	metadata := map[string]any{"name": name}
	if namespace != "" {
		metadata["namespace"] = namespace
	}
	kind := "Issuer"
	if resource == clusterIssuerResource {
		kind = "ClusterIssuer"
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": CertManagerGroup + "/" + CertManagerVersion,
		"kind":       kind,
		"metadata":   metadata,
		"spec":       spec,
	}}
}

func TestScanCertManager(t *testing.T) {
	_, chain, _ := generateChain(t)
	secret := tlsSecret("payments", "db-tls", map[string][]byte{"tls.crt": chain}, nil)
	certificate := certificateObject("payments", "db", map[string]any{
		"secretName":            "db-tls",
		"duration":              "2160h",
		"renewBefore":           "720h",
		"renewBeforePercentage": int64(50),
		"issuerRef":             map[string]any{"name": "letsencrypt", "kind": ClusterIssuerKind},
	}, map[string]any{
		"notAfter":    "2026-04-01T00:00:00Z",
		"renewalTime": "2026-03-01T00:00:00Z",
		"conditions":  []any{map[string]any{"type": "Ready", "status": "True", "reason": "Ready"}},
	})
	certificate.SetLabels(map[string]string{"scadenza.io/owner": "team-pay"})
	issuer := issuerObject(clusterIssuerResource, "", "letsencrypt", map[string]any{
		"acme": map[string]any{"server": "https://acme-v02.api.letsencrypt.org/directory", "privateKeySecretRef": map[string]any{"name": "should-not-be-read"}},
	})
	scanner := scannerWith(t, testOptions(t, ""), []runtime.Object{secret}, []*unstructured.Unstructured{certificate, issuer}, certManagerListKinds())

	result, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(result.Certificates) != 1 {
		t.Fatalf("certificates = %+v", result.Certificates)
	}
	certificateResult := result.Certificates[0]
	if len(certificateResult.Observations) != 2 {
		t.Fatalf("observations = %+v", certificateResult.Observations)
	}
	if len(certificateResult.Owners) != 1 || certificateResult.Owners[0].Source != owner.SourceLabel {
		t.Fatalf("owners = %+v", certificateResult.Owners)
	}
	facts := certificateResult.Observations[0].Kubernetes
	if facts == nil || facts.IssuerType != IssuerTypeACME || facts.ACMEServer != "https://acme-v02.api.letsencrypt.org/directory" {
		t.Fatalf("facts = %+v", facts)
	}
	if facts.Duration != "2160h" || facts.RenewBefore != "720h" || facts.RenewBeforePercentage != "50" || facts.NotAfter != "2026-04-01T00:00:00Z" || facts.RenewalTime != "2026-03-01T00:00:00Z" || facts.Ready != "True" {
		t.Fatalf("raw facts = %+v", facts)
	}
	if strings.Contains(fmt.Sprintf("%+v", facts), "should-not-be-read") {
		t.Fatalf("privateKeySecretRef content leaked: %+v", facts)
	}
}

func TestScanCertManagerWithoutSecret(t *testing.T) {
	certificate := certificateObject("payments", "orphan", map[string]any{
		"secretName": "missing-tls",
		"issuerRef":  map[string]any{"name": "ca-issuer"},
	}, nil)
	scanner := scannerWith(t, testOptions(t, ""), nil, []*unstructured.Unstructured{certificate}, certManagerListKinds())
	result, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(result.Certificates) != 1 {
		t.Fatalf("certificates = %+v", result.Certificates)
	}
	orphan := result.Certificates[0]
	if orphan.Fingerprint != "" || orphan.DedupKey != "cert-manager/payments/orphan" {
		t.Fatalf("orphan = %+v", orphan)
	}
	if orphan.Observations[0].Kubernetes.IssuerType != IssuerTypeUnknown {
		t.Fatalf("issuer type = %q", orphan.Observations[0].Kubernetes.IssuerType)
	}
}

func TestIssuerTypeResolution(t *testing.T) {
	index := issuerIndex{
		namespaced: map[string]map[string]any{
			"payments/ca":       {"ca": map[string]any{"secretName": "ca-key"}},
			"payments/self":     {"selfSigned": map[string]any{}},
			"payments/vault":    {"vault": map[string]any{"server": "https://vault"}},
			"payments/venafi":   {"venafi": map[string]any{}},
			"payments/mystery":  {"unknownThing": map[string]any{}},
			"payments/acme":     {"acme": map[string]any{"server": "https://acme.example.com/dir"}},
			"payments/scalar":   {"ca": "not-a-map"},
			"payments/multiple": {"ca": map[string]any{}, "vault": map[string]any{}},
			"payments/empty":    {},
		},
		cluster: map[string]map[string]any{
			"cluster-ca": {"ca": map[string]any{}},
		},
	}
	tests := []struct {
		name      string
		namespace string
		group     string
		kind      string
		issuer    string
		wantType  string
		wantACME  string
	}{
		{"namespaced acme", "payments", "", IssuerKind, "acme", IssuerTypeACME, "https://acme.example.com/dir"},
		{"default issuer kind", "payments", CertManagerGroup, "", "ca", IssuerTypeCA, ""},
		{"namespaced ca", "payments", "", IssuerKind, "ca", IssuerTypeCA, ""},
		{"self signed", "payments", "", IssuerKind, "self", IssuerTypeSelfSigned, ""},
		{"vault", "payments", "", IssuerKind, "vault", IssuerTypeVault, ""},
		{"venafi", "payments", "", IssuerKind, "venafi", IssuerTypeVenafi, ""},
		{"cluster issuer ca", "payments", "", ClusterIssuerKind, "cluster-ca", IssuerTypeCA, ""},
		{"foreign group is external", "payments", "other.example.io", IssuerKind, "anything", IssuerTypeExternal, ""},
		{"unknown issuer kind", "payments", "", "OtherIssuer", "ca", IssuerTypeUnknown, ""},
		{"recognized scalar is unknown", "payments", "", IssuerKind, "scalar", IssuerTypeUnknown, ""},
		{"multiple recognized maps are unknown", "payments", "", IssuerKind, "multiple", IssuerTypeUnknown, ""},
		{"missing issuer is unknown", "payments", "", IssuerKind, "absent", IssuerTypeUnknown, ""},
		{"unrecognized spec is unknown", "payments", "", IssuerKind, "mystery", IssuerTypeUnknown, ""},
		{"empty spec is unknown", "payments", "", IssuerKind, "empty", IssuerTypeUnknown, ""},
		{"missing name is unknown", "payments", "", IssuerKind, "", IssuerTypeUnknown, ""},
		{"wrong namespace is unknown", "other", "", IssuerKind, "ca", IssuerTypeUnknown, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotType, gotACME := index.resolve(test.namespace, test.group, test.kind, test.issuer)
			if gotType != test.wantType || gotACME != test.wantACME {
				t.Fatalf("resolve = (%q, %q), want (%q, %q)", gotType, gotACME, test.wantType, test.wantACME)
			}
		})
	}
}

func TestScanForbidden(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	client.PrependReactor("list", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "secrets", errors.New("denied"))
	})
	scanner := New(Clients{
		Kubernetes: client,
		Dynamic:    dynamicfake.NewSimpleDynamicClientWithCustomListKinds(schemeWithCertManager(), certManagerListKinds()),
	}, testOptions(t, ""))

	result, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(result.Problems) == 0 || result.Problems[0].Code != CodeForbidden {
		t.Fatalf("problems = %+v", result.Problems)
	}
}

func TestScanUnreachable(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	client.PrependReactor("list", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("connection refused")
	})
	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(schemeWithCertManager(), certManagerListKinds())
	dynamicClient.PrependReactor("list", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("connection refused")
	})
	scanner := New(Clients{Kubernetes: client, Dynamic: dynamicClient}, testOptions(t, ""))
	result, err := scanner.Scan(context.Background())
	if err == nil {
		t.Fatalf("Scan = nil error, problems %+v", result.Problems)
	}
	if !errors.Is(err, errUnreachable) {
		t.Fatalf("err = %v", err)
	}
	if len(result.Problems) == 0 || result.Problems[0].Code != CodeUnreachable {
		t.Fatalf("problems = %+v", result.Problems)
	}
}

func TestScanAvailabilityUsesSuccessfulLists(t *testing.T) {
	t.Run("empty secrets list survives cert-manager transport failure", func(t *testing.T) {
		dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(schemeWithCertManager(), certManagerListKinds())
		dynamicClient.PrependReactor("list", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("transport failed")
		})
		scanner := New(Clients{Kubernetes: k8sfake.NewSimpleClientset(), Dynamic: dynamicClient}, testOptions(t, ""))
		if _, err := scanner.Scan(context.Background()); err != nil {
			t.Fatalf("Scan: %v", err)
		}
	})

	t.Run("all forbidden fails source", func(t *testing.T) {
		coreClient := k8sfake.NewSimpleClientset()
		coreClient.PrependReactor("list", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "", errors.New("denied"))
		})
		dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(schemeWithCertManager(), certManagerListKinds())
		dynamicClient.PrependReactor("list", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "certificates"}, "", errors.New("denied"))
		})
		scanner := New(Clients{Kubernetes: coreClient, Dynamic: dynamicClient}, testOptions(t, ""))
		if _, err := scanner.Scan(context.Background()); !errors.Is(err, errUnreachable) {
			t.Fatalf("Scan error = %v", err)
		}
	})

	t.Run("unauthorized is fatal despite another successful kind", func(t *testing.T) {
		coreClient := k8sfake.NewSimpleClientset()
		coreClient.PrependReactor("list", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewUnauthorized("expired token")
		})
		scanner := New(Clients{Kubernetes: coreClient, Dynamic: dynamicfake.NewSimpleDynamicClientWithCustomListKinds(schemeWithCertManager(), certManagerListKinds())}, testOptions(t, ""))
		result, err := scanner.Scan(context.Background())
		if !errors.Is(err, errUnreachable) {
			t.Fatalf("Scan error = %v", err)
		}
		for _, problem := range result.Problems {
			if problem.Code == CodeForbidden {
				t.Fatalf("unauthorized classified as forbidden: %+v", problem)
			}
		}
	})
}

func TestClientErrorsAreStructuredAndSanitized(t *testing.T) {
	const secret = "fake-token -----BEGIN PRIVATE KEY----- fake-pem"
	problem, fatal := classify(apierrors.NewUnauthorized(secret), "secrets", "payments", false)
	encoded, err := json.Marshal(problem)
	if err != nil {
		t.Fatal(err)
	}
	if !fatal || problem.Code != CodeUnreachable || problem.HTTPStatus != 401 || problem.Reason != metav1.StatusReasonUnauthorized {
		t.Fatalf("problem = %+v fatal=%v", problem, fatal)
	}
	if strings.Contains(string(encoded), "fake-token") || strings.Contains(string(encoded), "PRIVATE KEY") {
		t.Fatalf("raw error leaked: %s", encoded)
	}
	coreNotFound, _ := classify(apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, "missing"), "secrets", "typo", false)
	if coreNotFound.Code == CodeCRDMissing {
		t.Fatalf("core 404 classified as missing CRD: %+v", coreNotFound)
	}
}

func TestSecretsScrubPartialListBeforeError(t *testing.T) {
	partial := &corev1.SecretList{Items: []corev1.Secret{{Data: map[string][]byte{tlsPrivateKey: []byte(keyMaterial)}, StringData: map[string]string{tlsPrivateKey: keyMaterial}}}}
	client := k8sfake.NewSimpleClientset()
	client.PrependReactor("list", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, partial, errors.New("malformed page")
	})
	scanner := New(Clients{Kubernetes: client}, testOptions(t, ""))
	listed := false
	for range scanner.secrets(context.Background(), "payments", &listed) {
	}
	if _, ok := partial.Items[0].Data[tlsPrivateKey]; ok {
		t.Fatal("tls.key retained in Data")
	}
	if _, ok := partial.Items[0].StringData[tlsPrivateKey]; ok {
		t.Fatal("tls.key retained in StringData")
	}
}

func TestScanCRDMissing(t *testing.T) {
	_, chain, _ := generateChain(t)
	secret := tlsSecret("payments", "db", map[string][]byte{"tls.crt": chain}, nil)
	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(schemeWithCertManager(), map[schema.GroupVersionResource]string{})
	dynamicClient.PrependReactor("list", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, runtime.NewNotRegisteredErrForKind("CertificateList", schema.GroupVersionKind{Group: CertManagerGroup, Version: CertManagerVersion, Kind: "CertificateList"})
	})
	scanner := New(Clients{Kubernetes: k8sfake.NewSimpleClientset(secret), Dynamic: dynamicClient}, testOptions(t, ""))
	result, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(result.Certificates) != 1 {
		t.Fatalf("certificates = %+v", result.Certificates)
	}
	found := false
	for _, problem := range result.Problems {
		if problem.Code == CodeCRDMissing {
			found = true
		}
	}
	if !found {
		t.Fatalf("problems = %+v", result.Problems)
	}
}

func TestScanNamespaceScope(t *testing.T) {
	_, chain, _ := generateChain(t)
	secrets := []runtime.Object{
		tlsSecret("payments", "a", map[string][]byte{"tls.crt": chain}, nil),
		tlsSecret("other", "b", map[string][]byte{"tls.crt": chain}, nil),
	}
	scanner := scannerWith(t, testOptions(t, ""), secrets, nil, certManagerListKinds())
	result, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Certificates) != 2 {
		t.Fatalf("unscoped certificates = %d", len(result.Certificates))
	}
	options := testOptions(t, "")
	options.Namespaces = []string{"other", "other", ""}
	scoped := scannerWith(t, options, secrets, nil, certManagerListKinds())
	result, err = scoped.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Certificates) != 1 || result.Certificates[0].Observations[0].Location != "other/b" {
		t.Fatalf("scoped certificates = %+v", result.Certificates)
	}
}

func TestPaginate(t *testing.T) {
	pages := [][]int{{1, 2}, {3}, {}}
	calls := 0
	collected := []int{}
	for value, err := range paginate(context.Background(), 2, func(_ context.Context, _ metav1.ListOptions) ([]int, string, error) {
		page := pages[calls]
		calls++
		if calls >= len(pages) {
			return page, "", nil
		}
		return page, fmt.Sprintf("token-%d", calls), nil
	}) {
		if err != nil {
			t.Fatalf("paginate: %v", err)
		}
		collected = append(collected, value)
	}
	if calls != 3 || len(collected) != 3 || collected[0] != 1 || collected[2] != 3 {
		t.Fatalf("calls=%d collected=%v", calls, collected)
	}

	failure := errors.New("boom")
	var got error
	for _, err := range paginate(context.Background(), 1, func(context.Context, metav1.ListOptions) ([]int, string, error) {
		return nil, "", failure
	}) {
		got = err
	}
	if !errors.Is(got, failure) {
		t.Fatalf("err = %v", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls, yielded := 0, 0
	for _, err := range paginate(ctx, 3, func(context.Context, metav1.ListOptions) ([]int, string, error) {
		calls++
		return []int{1, 2, 3}, "more", nil
	}) {
		if err == nil {
			yielded++
			cancel()
		}
	}
	if calls != 1 || yielded != 1 {
		t.Fatalf("canceled pagination calls=%d yielded=%d", calls, yielded)
	}
}

func TestScope(t *testing.T) {
	tests := []struct {
		namespaces []string
		want       []string
	}{
		{nil, []string{""}},
		{[]string{"b", "a", "a"}, []string{"a", "b"}},
		{[]string{"  "}, []string{""}},
	}
	for _, test := range tests {
		scanner := New(Clients{}, Options{Namespaces: test.namespaces})
		got := scanner.scope()
		if strings.Join(got, ",") != strings.Join(test.want, ",") {
			t.Fatalf("scope(%v) = %v, want %v", test.namespaces, got, test.want)
		}
	}
}

// metadataHTTPScanner builds the real metadata client through the same
// constructor Load uses, pointed at an httptest server. The namespace and
// cert-manager clients are fakes, so only the Secret metadata path goes over
// HTTP.
func metadataHTTPScanner(t *testing.T, server *httptest.Server) *Scanner {
	t.Helper()
	client, err := newMetadataClient(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatalf("newMetadataClient: %v", err)
	}
	owners, err := owner.ParseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	return New(Clients{
		Kubernetes: k8sfake.NewSimpleClientset(),
		Metadata:   client,
		Dynamic: dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
			schemeWithCertManager(), certManagerListKinds(),
		),
	}, Options{Clock: clock.Fixed{Time: testNow}, Owners: owners})
}

func assertPartialMetadataAccept(t *testing.T, accept string) {
	t.Helper()
	if !strings.Contains(accept, "as=PartialObjectMetadataList") {
		t.Fatalf("Accept = %q; want a PartialObjectMetadataList media type", accept)
	}
	for _, part := range strings.Split(accept, ",") {
		if strings.EqualFold(strings.TrimSpace(part), "application/json") {
			t.Fatalf("Accept = %q still offers a bare application/json fallback", accept)
		}
	}
}

// TestScanMetadataOnlyAcceptsPartialObjectMetadataList proves a server that
// honours as=PartialObjectMetadataList is read successfully and that the
// request never asks for a full object.
func TestScanMetadataOnlyAcceptsPartialObjectMetadataList(t *testing.T) {
	var accept string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		accept = request.Header.Get("Accept")
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"kind":"PartialObjectMetadataList","apiVersion":"v1","items":[{"metadata":{"name":"db-tls","namespace":"payments","annotations":{"cert-manager.io/certificate-name":"db"}}}]}`)
	}))
	defer server.Close()

	result, err := metadataHTTPScanner(t, server).Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(result.Certificates) != 1 {
		t.Fatalf("certificates = %+v", result.Certificates)
	}
	certificate := result.Certificates[0]
	if certificate.DedupKey != "secret-metadata/payments/db-tls" ||
		len(certificate.Observations) != 1 || certificate.Observations[0].Source != SourceSecretMetadata {
		t.Fatalf("metadata certificate = %+v", certificate)
	}
	assertPartialMetadataAccept(t, accept)
}

// TestScanMetadataOnlyRejectsFullSecretList proves a server that ignores the
// as= parameter and answers with a full SecretList is refused, and that no
// Secret key material reaches the result, the problems, or the error.
func TestScanMetadataOnlyRejectsFullSecretList(t *testing.T) {
	const privateKeyMarker = "PRIVATEKEYBYTESMUSTNOTLEAK"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"kind":"SecretList","apiVersion":"v1","items":[{"metadata":{"name":"db-tls","namespace":"payments"},"data":{"tls.key":"`+privateKeyMarker+`"}}]}`)
	}))
	defer server.Close()

	result, err := metadataHTTPScanner(t, server).Scan(context.Background())
	if len(result.Certificates) != 0 {
		t.Fatalf("certificates retained from a full SecretList: %+v", result.Certificates)
	}
	if len(result.Problems) != 1 || result.Problems[0].Code != CodeUnreachable || result.Problems[0].Resource != "secrets" {
		t.Fatalf("problems = %+v", result.Problems)
	}
	haystack := fmt.Sprint(result)
	encoded, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	haystack += string(encoded)
	if err != nil {
		haystack += err.Error()
	}
	if strings.Contains(haystack, privateKeyMarker) {
		t.Fatalf("Secret key material leaked: %s", haystack)
	}
}

// TestScanMetadataOnlyPreservesForbiddenStatus proves the transport does not
// mask an API error response (the response is checked only on success), so
// RBAC denials still classify as SCD-0015.
func TestScanMetadataOnlyPreservesForbiddenStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(writer, `{"kind":"Status","apiVersion":"v1","status":"Failure","message":"secrets is forbidden","reason":"Forbidden","code":403}`)
	}))
	defer server.Close()

	result, _ := metadataHTTPScanner(t, server).Scan(context.Background())
	if len(result.Problems) != 1 || result.Problems[0].Code != CodeForbidden || result.Problems[0].Resource != "secrets" {
		t.Fatalf("problems = %+v", result.Problems)
	}
}

// TestScanCannotRaiseKlogVerbosity guards the invariant that no user can raise
// klog verbosity to >= 8, where client-go logs full API response bodies
// (including tls.key) before the Secret data read drops them.
func TestScanCannotRaiseKlogVerbosity(t *testing.T) {
	if flag.Lookup("v") != nil {
		t.Fatal("a -v flag is registered; klog verbosity could be raised to log full response bodies")
	}
	if klog.V(8).Enabled() {
		t.Fatal("klog verbosity is >= 8; full response bodies, including Secret data, would be logged")
	}
}

// TestRestConfigBoundsRequests proves the loaded REST configuration carries a
// request timeout, so a hung API server cannot hang a scan. The kubeconfig
// points at an unroutable dummy server and no request is ever made.
func TestRestConfigBoundsRequests(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kubeconfig")
	kubeconfig := "apiVersion: v1\n" +
		"kind: Config\n" +
		"clusters:\n" +
		"- cluster:\n" +
		"    server: https://127.0.0.1:1\n" +
		"  name: dummy\n" +
		"contexts:\n" +
		"- context:\n" +
		"    cluster: dummy\n" +
		"    user: dummy\n" +
		"  name: dummy\n" +
		"current-context: dummy\n" +
		"users:\n" +
		"- name: dummy\n" +
		"  user:\n" +
		"    token: dummy-token\n"
	if err := os.WriteFile(path, []byte(kubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}

	config, err := restConfig(LoadOptions{Kubeconfig: path})
	if err != nil {
		t.Fatal(err)
	}
	if config.Timeout != requestTimeout {
		t.Fatalf("timeout = %v, want %v", config.Timeout, requestTimeout)
	}
	if config.QPS != defaultQPS || config.Burst != defaultQPS*2 {
		t.Fatalf("qps = %v, burst = %d, want %v and %d", config.QPS, config.Burst, defaultQPS, defaultQPS*2)
	}
}
