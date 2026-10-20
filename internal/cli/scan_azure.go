package cli

import (
	"context"
	"errors"
	"strconv"

	"github.com/HarnageaGabriel/scadenza/internal/azurekv"
	"github.com/HarnageaGabriel/scadenza/internal/inventory"
	"github.com/HarnageaGabriel/scadenza/internal/owner"
)

type azureScanState struct {
	requested    bool
	available    bool
	partial      bool
	certificates []azurekv.Certificate
}

func validateAzureOptions(vaultURLs []string, qps float64, qpsChanged bool, hasTargets, hasKube bool) error {
	if qps <= 0 {
		return errors.New("--azure-qps must be positive")
	}
	if qpsChanged && len(vaultURLs) == 0 {
		return errors.New("--azure-qps requires --azure-keyvault")
	}
	for _, vaultURL := range vaultURLs {
		if err := azurekv.ValidateVaultURL(vaultURL); err != nil {
			return err
		}
	}
	if len(vaultURLs) == 0 && !hasTargets && !hasKube {
		return errors.New("supply at least one --domain, --host, --hosts-file, --kube, or --azure-keyvault")
	}
	return nil
}

func readAzureKeyVault(
	ctx context.Context,
	loader azureLoader,
	vaultURLs []string,
	qps float64,
	userAgent string,
	owners owner.Config,
	diagnostics *diagnosticSet,
	stderr writer,
) azureScanState {
	state := azureScanState{requested: len(vaultURLs) > 0}
	if !state.requested || loader == nil {
		return state
	}
	source, err := loader(azurekv.LoadOptions{
		VaultURLs: vaultURLs,
		QPS:       qps,
		UserAgent: userAgent,
		Owners:    owners,
	})
	if err != nil {
		emitDiagnostic(stderr, "SCD-0032", "vault_host="+safeAzureHost(vaultURLs))
		diagnostics.add("SCD-0032", "")
		return state
	}
	certificates, problems, scanErr := source.Scan(ctx)
	if interrupted(ctx) {
		// The run was stopped by a signal: it reports nothing, so the
		// cancelled read is not turned into a source problem.
		return state
	}
	for _, problem := range problems {
		code := azureProblemCode(problem)
		diagnostics.add(code, "")
		emitDiagnostic(stderr, code, azureProblemDetail(problem))
	}
	if scanErr != nil {
		kind, status, host := azureErrorDetails(scanErr, vaultURLs)
		if kind == azurekv.ErrorCanceled {
			diagnostics.add("SCD-0032", "")
			emitDiagnostic(stderr, "SCD-0032", azureErrorDetail(status, host))
			return state
		}
		problemAvailable := successfulAzureVaults(vaultURLs, problems) > 0
		state.available = len(problems) > 0 && problemAvailable
		state.partial = state.available
		switch kind {
		case azurekv.ErrorUnauthorized:
			diagnostics.add("SCD-0030", "")
			emitDiagnostic(stderr, "SCD-0030", azureErrorDetail(status, host))
		case azurekv.ErrorForbidden:
			diagnostics.add("SCD-0031", "")
			emitDiagnostic(stderr, "SCD-0031", azureErrorDetail(status, host))
			state.partial = true
			state.available = true
		default:
			diagnostics.add("SCD-0032", "")
			emitDiagnostic(stderr, "SCD-0032", azureErrorDetail(status, host))
		}
		if !state.available {
			return state
		}
	} else {
		problemAvailable := successfulAzureVaults(vaultURLs, problems) > 0
		state.available = problemAvailable
		state.partial = state.available && len(problems) > 0
	}
	state.certificates = certificates
	return state
}

func azureCoverage(requested, available, partial bool) inventory.SourceCoverage {
	entry := inventory.SourceCoverage{Name: azurekv.SourceName, Status: inventory.SourceStatusNotRequested, Detail: "not requested"}
	if requested {
		switch {
		case partial:
			entry.Status = inventory.SourceStatusPartial
			entry.Detail = "one or more vault or certificate reads failed"
		case available:
			entry.Status = inventory.SourceStatusOK
			entry.Detail = "queried"
		default:
			entry.Status = inventory.SourceStatusFailed
			entry.Detail = "source unavailable"
		}
	}
	return entry
}

func azureProblemCode(problem azurekv.Problem) string {
	switch problem.Kind {
	case azurekv.ErrorUnauthorized:
		return "SCD-0030"
	case azurekv.ErrorForbidden:
		return "SCD-0031"
	default:
		if problem.VaultUnavailable {
			return "SCD-0032"
		}
		return "SCD-0033"
	}
}

func successfulAzureVaults(vaultURLs []string, problems []azurekv.Problem) int {
	failed := map[string]bool{}
	for _, problem := range problems {
		if problem.VaultUnavailable {
			failed[problem.VaultHost] = true
		}
	}
	vaults := map[string]bool{}
	for _, vaultURL := range vaultURLs {
		host, err := azurekv.ParseVaultHost(vaultURL)
		if err == nil {
			vaults[host] = true
		}
	}
	read := 0
	for host := range vaults {
		if !failed[host] {
			read++
		}
	}
	return read
}

func azureProblemDetail(problem azurekv.Problem) string {
	return azureErrorDetail(problem.HTTPStatus, problem.VaultHost)
}

func azureErrorDetails(err error, vaultURLs []string) (azurekv.ErrorKind, int, string) {
	var sourceErr *azurekv.Error
	if errors.As(err, &sourceErr) {
		return sourceErr.Problem.Kind, sourceErr.Problem.HTTPStatus, sourceErr.Problem.VaultHost
	}
	return azurekv.ErrorUnreachable, 0, safeAzureHost(vaultURLs)
}

func azureErrorDetail(status int, host string) string {
	result := ""
	if status != 0 {
		result = "http_status=" + strconv.Itoa(status) + " "
	}
	return result + "vault_host=" + host
}

func safeAzureHost(vaultURLs []string) string {
	if len(vaultURLs) == 0 {
		return ""
	}
	parsed, err := azurekv.ParseVaultHost(vaultURLs[0])
	if err != nil {
		return ""
	}
	return parsed
}

type writer interface {
	Write([]byte) (int, error)
}
