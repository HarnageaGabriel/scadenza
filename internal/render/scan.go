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
}

// Scan writes a scan document as table, JSON, or CSV.
func Scan(writer io.Writer, format string, document ScanDocument) error {
	switch format {
	case "json":
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
	if err := output.Write([]string{"fingerprint_sha256", "serial", "names", "issuer", "not_before", "not_after", "lifetime_days", "verdict_100d", "public", "source", "location", "detail"}); err != nil {
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
	if _, err := fmt.Fprintln(certificates, "FINGERPRINT SHA256\tSERIAL\tDAYS\t100D\tPUBLIC\tOBSERVATIONS\tISSUER\tNAMES"); err != nil {
		return err
	}
	for _, certificate := range document.Certificates {
		if _, err := fmt.Fprintf(certificates, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
			displayFingerprint(certificate.Fingerprint),
			certificate.Serial,
			certificate.LifetimeDays,
			certificate.Verdict100D,
			publicText(certificate.Public),
			displayObservations(certificate.Observations),
			certificate.Issuer,
			displayNames(certificate.Names),
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
		if _, err := fmt.Fprintf(findings, "%s\t%s\t%s\t%s\n", finding.Kind, displayFingerprint(finding.Fingerprint), displayNames(finding.Names), finding.Detail); err != nil {
			return err
		}
	}
	return findings.Flush()
}

func displayFingerprint(value string) string {
	if value == "" {
		return "-"
	}
	return value
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
