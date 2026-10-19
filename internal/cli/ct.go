package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/azurekv"
	"github.com/HarnageaGabriel/scadenza/internal/clock"
	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/diag"
	"github.com/HarnageaGabriel/scadenza/internal/httpx"
	"github.com/HarnageaGabriel/scadenza/internal/kube"
	"github.com/HarnageaGabriel/scadenza/internal/render"
	"github.com/HarnageaGabriel/scadenza/internal/tlsprobe"
	"github.com/HarnageaGabriel/scadenza/internal/version"
	"github.com/spf13/cobra"
)

type ctDependencies struct {
	clock     clock.Clock
	sources   map[string]ct.Source
	prober    hostProber
	loadKube  kubeLoader
	loadAzure azureLoader
}

// kubeLoader builds a read-only Kubernetes source from CLI options. It is
// injectable so tests can run without a cluster.
type (
	kubeLoader   func(load kube.LoadOptions, scan kube.Options) (kube.Source, error)
	azureLoader  func(load azurekv.LoadOptions) (azurekv.Source, error)
	commandError struct {
		code int
		err  error
	}
)

func (e *commandError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return "command failed"
}
func (e *commandError) Unwrap() error { return e.err }

// usageArgs wraps a cobra argument validator so its failures exit as usage errors.
func usageArgs(validate cobra.PositionalArgs) cobra.PositionalArgs {
	return func(command *cobra.Command, args []string) error {
		if err := validate(command, args); err != nil {
			return &commandError{code: ExitUsageError, err: err}
		}
		return nil
	}
}

func productionCTDependencies() ctDependencies {
	certClient := httpx.New(version.Version, httpx.NewIntervalLimiter(time.Second))
	crtClient := httpx.New(version.Version, httpx.NewIntervalLimiter(12*time.Second))
	return ctDependencies{clock: clock.System{}, sources: map[string]ct.Source{
		"certspotter": &ct.CertSpotter{Client: certClient, URL: "https://api.certspotter.com/v1/issuances", APIKey: os.Getenv("SCADENZA_CERTSPOTTER_KEY")},
		"crtsh":       &ct.CrtSH{Client: crtClient, URL: "https://crt.sh/"},
	}, prober: tlsprobe.New(), loadKube: kube.Load, loadAzure: azurekv.Load}
}

func newCTCommand(stdout, stderr io.Writer, dependencies ctDependencies) *cobra.Command {
	var sourceNames []string
	var includeSubdomains, expired bool
	var format string
	var maximum int
	var nowFlag string
	command := &cobra.Command{
		Use: "ct <domain>", Short: "List certificates issued for a domain", Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(command *cobra.Command, args []string) error {
			domain, err := ct.NormalizeDomain(args[0])
			if err != nil {
				emitDiagnostic(stderr, "SCD-0001", "")
				return &commandError{code: ExitUsageError}
			}
			if maximum < 1 {
				emitDiagnostic(stderr, "SCD-0001", "--max-results must be positive")
				return &commandError{code: ExitUsageError}
			}
			if format != "table" && format != "json" && format != "csv" {
				emitDiagnostic(stderr, "SCD-0001", "--format must be table, json, or csv")
				return &commandError{code: ExitUsageError}
			}
			evaluationClock := dependencies.clock
			if strings.TrimSpace(nowFlag) != "" {
				parsed, parseErr := time.Parse(time.RFC3339, strings.TrimSpace(nowFlag))
				if parseErr != nil {
					emitDiagnostic(stderr, "SCD-0001", "--now must be an RFC 3339 timestamp")
					return &commandError{code: ExitUsageError}
				}
				evaluationClock = clock.Fixed{Time: parsed}
			}
			chosen := make([]ct.Source, 0, len(sourceNames))
			for _, name := range sourceNames {
				source, ok := dependencies.sources[name]
				if !ok {
					emitDiagnostic(stderr, "SCD-0001", "unknown source "+name)
					return &commandError{code: ExitUsageError}
				}
				chosen = append(chosen, source)
			}
			var certificates []ct.Certificate
			var used []string
			diagnostics := []diag.Diagnostic{}
			for index, source := range chosen {
				certificates, err = source.Search(command.Context(), ct.Query{Domain: domain, IncludeSubdomains: includeSubdomains, Limit: maximum + 1, Now: dependencies.clock.Now(), IncludeExpired: expired})
				if err == nil {
					used = []string{source.Name()}
					break
				}
				code := sourceErrorCode(err)
				diagnostic, _ := diag.Lookup(code)
				diagnostics = append(diagnostics, diagnostic)
				emitDiagnostic(stderr, code, source.Name())
				if index < len(chosen)-1 {
					fallback, _ := diag.Lookup("SCD-0007")
					diagnostics = append(diagnostics, fallback)
					emitDiagnostic(stderr, "SCD-0007", source.Name()+" -> "+chosen[index+1].Name())
				}
			}
			if err != nil {
				return &commandError{code: ExitSourceUnavailable}
			}
			now := evaluationClock.Now()
			certificates, truncated := ct.Finalize(certificates, now, expired, maximum)
			if truncated {
				item, _ := diag.Lookup("SCD-0006")
				diagnostics = append(diagnostics, item)
				emitDiagnostic(stderr, "SCD-0006", fmt.Sprint(maximum))
			}
			if len(certificates) == 0 {
				item, _ := diag.Lookup("SCD-0005")
				diagnostics = append(diagnostics, item)
				emitDiagnostic(stderr, "SCD-0005", domain)
			}
			document := render.CTDocument{SchemaVersion: "scadenza.ct/v1", Domain: domain, GeneratedAt: now.UTC(), SourcesUsed: used, Certificates: certificates, Diagnostics: diagnostics}
			if err := render.CT(stdout, format, document); err != nil {
				return fmt.Errorf("render output: %w", err)
			}
			return nil
		},
	}
	command.Flags().StringSliceVar(&sourceNames, "source", []string{"certspotter", "crtsh"}, "CT source order (certspotter, crtsh)")
	command.Flags().BoolVar(&includeSubdomains, "include-subdomains", true, "include subdomains")
	command.Flags().BoolVar(&expired, "expired", false, "include expired certificates")
	command.Flags().StringVar(&format, "format", "table", "output format: table, json, csv")
	command.Flags().IntVar(&maximum, "max-results", 1000, "maximum certificates to print")
	command.Flags().StringVar(&nowFlag, "now", "", "evaluation instant as an RFC 3339 timestamp; defaults to the current time")
	return command
}

func sourceErrorCode(err error) string {
	switch ct.Kind(err) {
	case ct.RateLimited:
		return "SCD-0003"
	case ct.Malformed:
		return "SCD-0004"
	default:
		return "SCD-0002"
	}
}

func emitDiagnostic(writer io.Writer, code, detail string) {
	emitDiagnosticSeverity(writer, code, detail, "")
}

func emitDiagnosticSeverity(writer io.Writer, code, detail string, severity diag.Severity) {
	item, ok := diag.Lookup(code)
	if !ok {
		return
	}
	if severity != "" {
		item.Severity = severity
	}
	suffix := ""
	if strings.TrimSpace(detail) != "" {
		suffix = ": " + detail
	}
	_, _ = fmt.Fprintf(writer, "%s [%s] %s%s\n", item.Severity, item.Code, item.Summary, suffix)
}

func exitCode(err error) int {
	var commandErr *commandError
	if errors.As(err, &commandErr) {
		return commandErr.code
	}
	return ExitInternalError
}
