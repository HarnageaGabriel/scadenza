//go:build e2e

// Package e2e exercises `scadenza scan --kube` against a real cluster.
//
// These tests never run by default: they need a Kubernetes cluster, a
// kubeconfig, and cert-manager. .github/workflows/e2e.yml installs kind and a
// pinned cert-manager, then runs `go test -tags e2e ./test/e2e/...`.
//
// The cluster is expected to hold a self-signed cert-manager ClusterIssuer and
// two Certificates in SCADENZA_E2E_NAMESPACE with different durations, both
// labelled scadenza.io/owner=team-e2e. The workflow creates them.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	kubeContextEnv        = "SCADENZA_E2E_KUBE_CONTEXT"
	secretsKubeconfigEnv  = "SCADENZA_E2E_SECRETS_KUBECONFIG"
	secretsKubeContextEnv = "SCADENZA_E2E_SECRETS_KUBE_CONTEXT"
	namespaceEnv          = "SCADENZA_E2E_NAMESPACE"
	ownerValue            = "team-e2e"
)

type observation struct {
	Source     string `json:"source"`
	Location   string `json:"location"`
	Kubernetes *struct {
		Resource   string `json:"resource"`
		Namespace  string `json:"namespace"`
		Name       string `json:"name"`
		SecretName string `json:"secret_name"`
		IssuerType string `json:"issuer_type"`
		Duration   string `json:"duration"`
	} `json:"kubernetes"`
}

type scanDocument struct {
	SourcesUsed  []string `json:"sources_used"`
	Certificates []struct {
		Fingerprint       string `json:"fingerprint_sha256"`
		LifetimeDays      int    `json:"lifetime_days"`
		Verdict100D       string `json:"verdict_100d"`
		CorrelationMethod string `json:"correlation_method"`
		Owners            []struct {
			Owner  string `json:"owner"`
			Source string `json:"owner_source"`
		} `json:"owners"`
		Observations []observation `json:"observations"`
	} `json:"certificates"`
	Diagnostics []struct {
		Code string `json:"code"`
	} `json:"diagnostics"`
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve the test file location")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// scan runs the built CLI with `--kube` and returns its JSON output. Exit code 3
// (findings present) is accepted; any other failure is fatal.
func scan(t *testing.T, kubeContext string, extraArgs ...string) ([]byte, []byte) {
	t.Helper()
	root := repoRoot(t)
	binary := filepath.Join(t.TempDir(), "scadenza")
	build := exec.Command("go", "build", "-o", binary, "./cmd/scadenza")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	args := []string{"scan", "--kube", "--kube-context", kubeContext, "--format", "json"}
	args = append(args, extraArgs...)
	command := exec.CommandContext(ctx, binary, args...)
	command.Dir = root
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 3 {
			t.Fatalf("scan: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.Bytes(), stderr.Bytes())
		}
	}
	return stdout.Bytes(), stderr.Bytes()
}

func TestScanKubernetesSource(t *testing.T) {
	kubeContext := os.Getenv(kubeContextEnv)
	if kubeContext == "" {
		t.Skipf("%s is not set; skipping the cluster e2e", kubeContextEnv)
	}
	namespace := os.Getenv(namespaceEnv)
	if namespace == "" {
		namespace = "scadenza-e2e"
	}

	output, scanErrors := scan(t, kubeContext)
	assertNoSecretData(t, output, scanErrors)
	var document scanDocument
	if err := json.Unmarshal(output, &document); err != nil {
		t.Fatalf("decode scan JSON: %v\n%s", err, output)
	}

	if !contains(document.SourcesUsed, "kube") {
		t.Fatalf("sources_used = %v, want kube", document.SourcesUsed)
	}
	foundSecretListWarning := false
	for _, diagnostic := range document.Diagnostics {
		if diagnostic.Code == "SCD-0014" {
			t.Fatalf("cluster was reported unreachable: %s", output)
		}
		if diagnostic.Code == "SCD-0015" {
			foundSecretListWarning = true
		}
	}
	if !foundSecretListWarning {
		t.Fatalf("default read-only scan did not document forbidden Secret metadata: %s", output)
	}

	locations := map[string]bool{}
	var certManagerTypes []string
	lifetimes := map[int]bool{}
	owners := map[string]string{}
	for _, certificate := range document.Certificates {
		lifetimes[certificate.LifetimeDays] = true
		for _, owner := range certificate.Owners {
			owners[owner.Owner] = owner.Source
		}
		if certificate.CorrelationMethod != "unresolved" {
			t.Errorf("correlation_method = %q, want unresolved without CT/TLS match", certificate.CorrelationMethod)
		}
		for _, observation := range certificate.Observations {
			locations[observation.Location] = true
			if observation.Kubernetes == nil {
				continue
			}
			if observation.Source == "cert-manager" {
				certManagerTypes = append(certManagerTypes, observation.Kubernetes.IssuerType)
			}
			if observation.Source == "kube-secret" {
				t.Errorf("default mode read Secret data: %+v", observation)
			}
		}
	}

	if len(certManagerTypes) == 0 {
		t.Fatal("no cert-manager Certificate observation was reported")
	}
	for _, issuerType := range certManagerTypes {
		if issuerType != "selfSigned" {
			t.Errorf("issuer_type = %q, want selfSigned for the self-signed ClusterIssuer", issuerType)
		}
	}
	if len(lifetimes) < 2 {
		t.Errorf("expected certificates with different durations; got lifetimes %v", sortedLifetimes(lifetimes))
	}
	if owners[ownerValue] == "" {
		t.Errorf("expected owner %q from a label; owners = %v", ownerValue, owners)
	}
	if !slices.IsSorted(fingerprints(document)) {
		t.Error("certificates are not sorted by fingerprint")
	}
}

func TestScanKubernetesSecretDataOptIn(t *testing.T) {
	kubeconfig := os.Getenv(secretsKubeconfigEnv)
	if kubeconfig == "" {
		t.Skipf("%s is not set; skipping the Secret-data cluster e2e", secretsKubeconfigEnv)
	}
	kubeContext := os.Getenv(secretsKubeContextEnv)
	if kubeContext == "" {
		t.Skipf("%s is not set; skipping the Secret-data cluster e2e", secretsKubeContextEnv)
	}
	namespace := os.Getenv(namespaceEnv)
	if namespace == "" {
		namespace = "scadenza-e2e"
	}

	output, scanErrors := scan(t, kubeContext, "--kubeconfig", kubeconfig, "--kube-secrets")
	assertNoSecretData(t, output, scanErrors)
	var document scanDocument
	if err := json.Unmarshal(output, &document); err != nil {
		t.Fatalf("decode scan JSON: %v\n%s", err, output)
	}
	if !contains(document.SourcesUsed, "kube") {
		t.Fatalf("sources_used = %v, want kube", document.SourcesUsed)
	}
	foundSecretReadDiagnostic := false
	for _, diagnostic := range document.Diagnostics {
		switch diagnostic.Code {
		case "SCD-0014":
			t.Fatalf("cluster was reported unreachable: %s", output)
		case "SCD-0015":
			t.Fatalf("secrets manifest still forbids Secret reads: %s", output)
		case "SCD-0029":
			foundSecretReadDiagnostic = true
		}
	}
	if !foundSecretReadDiagnostic {
		t.Fatalf("missing SCD-0029 Secret-data diagnostic: %s", output)
	}

	locations := map[string]bool{}
	fingerprinted := 0
	for _, certificate := range document.Certificates {
		if certificate.Fingerprint != "" {
			fingerprinted++
		}
		for _, observation := range certificate.Observations {
			locations[observation.Location] = true
		}
	}
	for _, secret := range []string{namespace + "/short-tls", namespace + "/long-tls"} {
		if !locations[secret] {
			t.Errorf("no typed Secret observation for %s; locations = %v", secret, sortedLocations(locations))
		}
	}
	if fingerprinted < 2 {
		t.Errorf("fingerprinted certificates = %d, want at least 2", fingerprinted)
	}
}

func assertNoSecretData(t *testing.T, output, scanErrors []byte) {
	t.Helper()
	for name, stream := range map[string]string{"stdout": string(output), "stderr": string(scanErrors)} {
		lower := strings.ToLower(stream)
		if strings.Contains(lower, "tls.key") || strings.Contains(lower, "private key") {
			t.Fatalf("%s contains Secret key material: %s", name, stream)
		}
	}
}

func fingerprints(document scanDocument) []string {
	result := make([]string, 0, len(document.Certificates))
	for _, certificate := range document.Certificates {
		result = append(result, certificate.Fingerprint)
	}
	return result
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func sortedLocations(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func sortedLifetimes(values map[int]bool) []int {
	result := make([]int, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Ints(result)
	return result
}
