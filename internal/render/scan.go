package render

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/diag"
	"github.com/HarnageaGabriel/scadenza/internal/inventory"
	"github.com/HarnageaGabriel/scadenza/internal/owner"
)

// ScanDocument is the stable scadenza.scan/v1 JSON envelope.
type ScanDocument struct {
	SchemaVersion string                  `json:"schema_version"`
	GeneratedAt   time.Time               `json:"generated_at"`
	Domains       []string                `json:"domains"`
	SourcesUsed   []string                `json:"sources_used"`
	Certificates  []inventory.Certificate `json:"certificates"`
	Findings      []inventory.Finding     `json:"findings"`
	Unresolved    []inventory.Unresolved  `json:"unresolved"`
	ProbeErrors   []inventory.ProbeError  `json:"probe_errors"`
	Diagnostics   []diag.Diagnostic       `json:"diagnostics"`
	Coverage      inventory.Coverage      `json:"coverage"`
}

// Scan writes a scan document as table, JSON, or CSV.
func Scan(writer io.Writer, format string, document ScanDocument) error {
	switch format {
	case "json":
		document.Domains = emptyIfNil(document.Domains)
		document.SourcesUsed = emptyIfNil(document.SourcesUsed)
		document.Certificates = emptyIfNil(document.Certificates)
		document.Findings = emptyIfNil(document.Findings)
		document.Unresolved = emptyIfNil(document.Unresolved)
		document.ProbeErrors = emptyIfNil(document.ProbeErrors)
		document.Diagnostics = emptyIfNil(document.Diagnostics)
		document.Coverage.Sources = emptyIfNil(document.Coverage.Sources)
		for index := range document.Certificates {
			document.Certificates[index].Names = emptyIfNil(document.Certificates[index].Names)
			document.Certificates[index].Observations = emptyIfNil(document.Certificates[index].Observations)
			document.Certificates[index].Owners = emptyIfNil(document.Certificates[index].Owners)
		}
		for index := range document.Findings {
			document.Findings[index].Names = emptyIfNil(document.Findings[index].Names)
		}
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(document)
	case "csv":
		return writeScanCSV(writer, document.Certificates)
	case "table":
		return writeScanTable(writer, document)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func writeScanCSV(writer io.Writer, certificates []inventory.Certificate) error {
	output := csv.NewWriter(writer)
	if err := output.Write([]string{"fingerprint_sha256", "serial", "names", "issuer", "not_before", "not_after", "lifetime_days", "verdict_100d", "public", "source", "location", "detail", "owners"}); err != nil {
		return err
	}
	for _, certificate := range certificates {
		observations := certificate.Observations
		if len(observations) == 0 {
			observations = []inventory.Observation{{}}
		}
		for _, observation := range observations {
			row := []string{
				csvSafe(certificate.Fingerprint),
				csvSafe(certificate.Serial),
				csvSafe(strings.Join(certificate.Names, " ")),
				csvSafe(certificate.Issuer),
				certificate.NotBefore.Format(time.RFC3339),
				certificate.NotAfter.Format(time.RFC3339),
				strconv.Itoa(certificate.LifetimeDays),
				csvSafe(certificate.Verdict100D),
				publicText(certificate.Public),
				csvSafe(observation.Source),
				csvSafe(observation.Location),
				csvSafe(observation.Detail),
				csvSafe(displayOwners(certificate.Owners)),
			}
			if err := output.Write(row); err != nil {
				return err
			}
		}
	}
	output.Flush()
	return output.Error()
}

func writeScanTable(writer io.Writer, document ScanDocument) error {
	certificates := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(certificates, "FINGERPRINT SHA256\tSERIAL\tDAYS\t100D\tPUBLIC\tOBSERVATIONS\tISSUER\tNAMES\tOWNERS"); err != nil {
		return err
	}
	for _, certificate := range document.Certificates {
		if _, err := fmt.Fprintf(certificates, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
			sanitizeCell(displayFingerprint(certificate.Fingerprint)),
			sanitizeCell(certificate.Serial),
			certificate.LifetimeDays,
			sanitizeCell(certificate.Verdict100D),
			publicText(certificate.Public),
			sanitizeCell(displayObservations(certificate.Observations)),
			sanitizeCell(certificate.Issuer),
			sanitizeCell(displayNames(certificate.Names)),
			sanitizeCell(displayOwners(certificate.Owners)),
		); err != nil {
			return err
		}
	}
	if err := certificates.Flush(); err != nil {
		return err
	}
	findings := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(findings, "FINDINGS"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(findings, "KIND\tFINGERPRINT\tNAMES\tDETAIL"); err != nil {
		return err
	}
	for _, finding := range document.Findings {
		if _, err := fmt.Fprintf(findings, "%s\t%s\t%s\t%s\n",
			sanitizeCell(finding.Kind),
			sanitizeCell(displayFingerprint(finding.Fingerprint)),
			sanitizeCell(displayNames(finding.Names)),
			sanitizeCell(finding.Detail),
		); err != nil {
			return err
		}
	}
	if err := findings.Flush(); err != nil {
		return err
	}
	return writeCoverageLine(writer, document.Coverage)
}

// writeCoverageLine always prints a one-line coverage summary after the table,
// so a partial scan never looks clean.
func writeCoverageLine(writer io.Writer, coverage inventory.Coverage) error {
	sources := make([]string, 0, len(coverage.Sources))
	for _, source := range coverage.Sources {
		sources = append(sources, source.Name+":"+source.Status)
	}
	_, err := fmt.Fprintf(writer,
		"COVERAGE requested=%d probed=%d failed=%d not_checked=%d ratio=%.2f%% sources=%s\n",
		coverage.TargetsRequested, coverage.TargetsProbed, coverage.TargetsFailed,
		coverage.NamesNotChecked, coverage.Ratio*100, sanitizeCell(strings.Join(sources, ",")),
	)
	return err
}

func displayFingerprint(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func displayOwners(owners []owner.Owner) string {
	if len(owners) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(owners))
	for _, entry := range owners {
		parts = append(parts, entry.Value+" ("+string(entry.Source)+")")
	}
	return strings.Join(parts, ", ")
}

func publicText(value *bool) string {
	switch {
	case value == nil:
		return "unknown"
	case *value:
		return "yes"
	default:
		return "no"
	}
}

func displayObservations(observations []inventory.Observation) string {
	if len(observations) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(observations))
	for _, observation := range observations {
		parts = append(parts, observation.Source)
	}
	return strings.Join(parts, ", ")
}
