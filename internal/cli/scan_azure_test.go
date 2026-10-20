package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HarnageaGabriel/scadenza/internal/azurekv"
	"github.com/HarnageaGabriel/scadenza/internal/inventory"
	"github.com/HarnageaGabriel/scadenza/internal/owner"
)

type azureSourceStub struct {
	certificates []azurekv.Certificate
	problems     []azurekv.Problem
	err          error
}

func (s azureSourceStub) Scan(context.Context) ([]azurekv.Certificate, []azurekv.Problem, error) {
	return s.certificates, s.problems, s.err
}

func TestReadAzureKeyVaultKeepsSuccessfulVaultResults(t *testing.T) {
	first := "https://first.vault.azure.net"
	second := "https://second.vault.azure.net"
	stub := azureSourceStub{
		certificates: []azurekv.Certificate{{Fingerprint: "fingerprint"}},
		problems: []azurekv.Problem{{
			Kind: azurekv.ErrorUnauthorized, HTTPStatus: 401, VaultHost: "second.vault.azure.net", VaultUnavailable: true,
		}},
	}
	state, output := runAzureRead(t, []string{first, second}, stub)
	if !state.available || !state.partial || len(state.certificates) != 1 {
		t.Fatalf("state=%+v", state)
	}
	if coverage := azureCoverage(state.requested, state.available, state.partial); coverage.Status != inventory.SourceStatusPartial {
		t.Fatalf("coverage=%+v", coverage)
	}
	if !strings.Contains(output, "SCD-0030") || !strings.Contains(output, "vault_host=second.vault.azure.net") {
		t.Fatalf("diagnostic=%q", output)
	}
}

func TestReadAzureKeyVaultCoverageAndProblemCodes(t *testing.T) {
	vault := "https://demo.vault.azure.net"
	for _, test := range []struct {
		name       string
		problem    azurekv.Problem
		wantStatus string
		wantCode   string
	}{
		{
			name:       "unauthorized vault failed",
			problem:    azurekv.Problem{Kind: azurekv.ErrorUnauthorized, HTTPStatus: 401, VaultHost: "demo.vault.azure.net", VaultUnavailable: true},
			wantStatus: inventory.SourceStatusFailed,
			wantCode:   "SCD-0030",
		},
		{
			name:       "forbidden list failed",
			problem:    azurekv.Problem{Kind: azurekv.ErrorForbidden, HTTPStatus: 403, VaultHost: "demo.vault.azure.net", VaultUnavailable: true},
			wantStatus: inventory.SourceStatusFailed,
			wantCode:   "SCD-0031",
		},
		{
			name:       "invalid item partial",
			problem:    azurekv.Problem{Kind: azurekv.ErrorInvalid, VaultHost: "demo.vault.azure.net"},
			wantStatus: inventory.SourceStatusPartial,
			wantCode:   "SCD-0033",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			state, output := runAzureRead(t, []string{vault}, azureSourceStub{problems: []azurekv.Problem{test.problem}})
			coverage := azureCoverage(state.requested, state.available, state.partial)
			if coverage.Status != test.wantStatus || !strings.Contains(output, test.wantCode) {
				t.Fatalf("state=%+v coverage=%+v diagnostic=%q", state, coverage, output)
			}
			if test.problem.HTTPStatus == 0 && strings.Contains(output, "http_status=") {
				t.Fatalf("zero HTTP status leaked into diagnostic=%q", output)
			}
		})
	}
}

func TestReadAzureKeyVaultCancellationAfterProblemFailsAndDropsCertificates(t *testing.T) {
	first := "https://first.vault.azure.net"
	second := "https://second.vault.azure.net"
	stub := azureSourceStub{
		certificates: []azurekv.Certificate{{Fingerprint: "must-be-dropped"}},
		problems: []azurekv.Problem{{
			Kind: azurekv.ErrorUnreachable, HTTPStatus: 404, VaultHost: "first.vault.azure.net",
		}},
		err: &azurekv.Error{Problem: azurekv.Problem{Kind: azurekv.ErrorCanceled, VaultHost: "second.vault.azure.net"}},
	}
	state, output := runAzureRead(t, []string{first, second}, stub)
	coverage := azureCoverage(state.requested, state.available, state.partial)
	if state.available || state.partial || len(state.certificates) != 0 || coverage.Status != inventory.SourceStatusFailed {
		t.Fatalf("state=%+v coverage=%+v", state, coverage)
	}
	if strings.Count(output, "SCD-0032") != 1 || !strings.Contains(output, "vault_host=second.vault.azure.net") {
		t.Fatalf("diagnostic=%q", output)
	}
}

func TestReadAzureKeyVaultSingleUnauthorizedErrorStillFails(t *testing.T) {
	vault := "https://demo.vault.azure.net"
	state, output := runAzureRead(t, []string{vault}, azureSourceStub{err: &azurekv.Error{Problem: azurekv.Problem{
		Kind: azurekv.ErrorUnauthorized, HTTPStatus: 401, VaultHost: "demo.vault.azure.net",
	}}})
	coverage := azureCoverage(state.requested, state.available, state.partial)
	if state.available || state.partial || coverage.Status != inventory.SourceStatusFailed || !strings.Contains(output, "SCD-0030") {
		t.Fatalf("state=%+v coverage=%+v diagnostic=%q", state, coverage, output)
	}
}

func runAzureRead(t *testing.T, vaults []string, source azurekv.Source) (azureScanState, string) {
	t.Helper()
	var stderr bytes.Buffer
	diagnostics := &diagnosticSet{}
	loader := func(azurekv.LoadOptions) (azurekv.Source, error) { return source, nil }
	state := readAzureKeyVault(context.Background(), loader, vaults, 1000, "test", owner.Config{}, diagnostics, &stderr)
	return state, stderr.String()
}

// paddedVaultURIs are vault URIs with surrounding whitespace. They are
// rejected instead of trimmed, so the diagnostic has to name the value.
var paddedVaultURIs = []struct {
	name  string
	value string
}{
	{name: "trailing space", value: "https://demo.vault.azure.net "},
	{name: "leading space", value: " https://demo.vault.azure.net"},
	{name: "trailing newline", value: "https://demo.vault.azure.net\n"},
}

func TestScanRejectsVaultURIWithSurroundingWhitespace(t *testing.T) {
	for _, test := range paddedVaultURIs {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := execute([]string{"scan", "--azure-keyvault", test.value}, &stdout, &stderr, scanDependencies("x", fakeProber{}))
			if code != ExitUsageError {
				t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), "SCD-0001") {
				t.Fatalf("stderr=%s", stderr.String())
			}
			if !strings.Contains(stderr.String(), "demo.vault.azure.net") {
				t.Fatalf("the diagnostic does not name the vault URI: %s", stderr.String())
			}
		})
	}
}

func TestScanRejectsConfigVaultURIWithSurroundingWhitespace(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "scadenza.yaml")
	document := "version: 1\nazure:\n  keyVaults: [\"https://demo.vault.azure.net \"]\n"
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := execute([]string{"scan", "--config", path}, &stdout, &stderr, scanDependencies("x", fakeProber{}))
	if code != ExitUsageError {
		t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "SCD-0001") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "demo.vault.azure.net") {
		t.Fatalf("the diagnostic does not name the vault URI: %s", stderr.String())
	}
}
