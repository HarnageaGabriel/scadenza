package render

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/diag"
	"github.com/HarnageaGabriel/scadenza/internal/inventory"
	"github.com/HarnageaGabriel/scadenza/internal/owner"
	"github.com/HarnageaGabriel/scadenza/internal/renewal"
)

// Table grouping modes for --group-by.
const (
	// GroupNone prints certificates in their deterministic order.
	GroupNone = "none"
	// GroupOwner groups table rows by the first declared owner.
	GroupOwner = "owner"
	// GroupNames groups table rows by the first certificate name.
	GroupNames = "names"
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
	// Owners is the M4b per-owner renewal workload summary.
	Owners   []renewal.OwnerSummary `json:"owners"`
	Coverage inventory.Coverage     `json:"coverage"`
}

// Scan writes a scan document as table, JSON, or CSV in the default grouping.
func Scan(writer io.Writer, format string, document ScanDocument) error {
	return ScanGrouped(writer, format, document, GroupNone)
}

// ScanGrouped is Scan with a table grouping mode. The grouping never changes
// JSON or CSV; it only reorders and labels the table rows.
func ScanGrouped(writer io.Writer, format string, document ScanDocument, groupBy string) error {
	for index := range document.Certificates {
		if document.Certificates[index].Renewal.Mode == "" {
			document.Certificates[index].Renewal.Mode = renewal.ModeUnknown
		}
		if document.Certificates[index].Renewal.Health == "" {
			document.Certificates[index].Renewal.Health = renewal.HealthUnknown
		}
	}
	switch format {
	case "json":
		document.Domains = emptyIfNil(document.Domains)
		document.SourcesUsed = emptyIfNil(document.SourcesUsed)
		document.Certificates = emptyIfNil(document.Certificates)
		document.Findings = emptyIfNil(document.Findings)
		document.Unresolved = emptyIfNil(document.Unresolved)
		document.ProbeErrors = emptyIfNil(document.ProbeErrors)
		document.Diagnostics = emptyIfNil(document.Diagnostics)
		document.Owners = emptyIfNil(document.Owners)
		document.Coverage.Sources = emptyIfNil(document.Coverage.Sources)
		for index := range document.Certificates {
			document.Certificates[index].Names = emptyIfNil(document.Certificates[index].Names)
			document.Certificates[index].Observations = emptyIfNil(document.Certificates[index].Observations)
			document.Certificates[index].Owners = emptyIfNil(document.Certificates[index].Owners)
			document.Certificates[index].Renewal.Evidence = emptyIfNil(document.Certificates[index].Renewal.Evidence)
			document.Certificates[index].Renewal.Risks = emptyIfNil(document.Certificates[index].Renewal.Risks)
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
		return writeScanTable(writer, document, groupBy)
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

func writeScanTable(writer io.Writer, document ScanDocument, groupBy string) error {
	certificates := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(certificates, "FINGERPRINT SHA256\tSERIAL\tDAYS\t100D\tMODE\tHEALTH\tPUBLIC\tOBSERVATIONS\tISSUER\tNAMES\tOWNERS"); err != nil {
		return err
	}
	for _, row := range groupedCertificates(document.Certificates, groupBy) {
		if row.header != "" {
			if _, err := fmt.Fprintln(certificates, sanitizeCell(row.header)); err != nil {
				return err
			}
		}
		certificate := row.certificate
		if _, err := fmt.Fprintf(certificates, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			sanitizeCell(displayFingerprint(certificate.Fingerprint)),
			sanitizeCell(certificate.Serial),
			certificate.LifetimeDays,
			sanitizeCell(certificate.Verdict100D),
			sanitizeCell(string(certificate.Renewal.Mode)),
			sanitizeCell(string(certificate.Renewal.Health)),
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
	if err := writeFindings(writer, document.Findings); err != nil {
		return err
	}
	if err := writeRisks(writer, document.Certificates); err != nil {
		return err
	}
	return writeCoverageLine(writer, document.Coverage)
}

func writeFindings(writer io.Writer, findings []inventory.Finding) error {
	output := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(output, "FINDINGS"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "KIND\tFINGERPRINT\tNAMES\tDETAIL"); err != nil {
		return err
	}
	for _, finding := range findings {
		if _, err := fmt.Fprintf(output, "%s\t%s\t%s\t%s\n",
			sanitizeCell(finding.Kind),
			sanitizeCell(displayFingerprint(finding.Fingerprint)),
			sanitizeCell(displayNames(finding.Names)),
			sanitizeCell(finding.Detail),
		); err != nil {
			return err
		}
	}
	return output.Flush()
}

// writeRisks prints the renewal risks as a summary at the end of the table. The
// section is omitted when no certificate has a risk.
func writeRisks(writer io.Writer, certificates []inventory.Certificate) error {
	output := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)
	rows := 0
	for _, certificate := range certificates {
		for _, risk := range certificate.Renewal.Risks {
			if rows == 0 {
				if _, err := fmt.Fprintln(output, "RISKS"); err != nil {
					return err
				}
				if _, err := fmt.Fprintln(output, "KIND\tFINGERPRINT\tNAMES\tEFFECTIVE\tDETAIL"); err != nil {
					return err
				}
			}
			rows++
			if _, err := fmt.Fprintf(output, "%s\t%s\t%s\t%s\t%s\n",
				sanitizeCell(risk.Kind),
				sanitizeCell(displayFingerprint(certificate.Fingerprint)),
				sanitizeCell(displayNames(certificate.Names)),
				sanitizeCell(displayEffective(risk.Effective)),
				sanitizeCell(risk.Detail),
			); err != nil {
				return err
			}
		}
	}
	if rows == 0 {
		return nil
	}
	return output.Flush()
}

// groupedRow is one certificate plus an optional group header line.
type groupedRow struct {
	header      string
	certificate inventory.Certificate
}

// groupedCertificates orders the rows for the requested grouping. Group keys are
// sorted and the certificate order inside a group is preserved, so the output
// stays deterministic. GroupNone leaves the order untouched.
func groupedCertificates(certificates []inventory.Certificate, groupBy string) []groupedRow {
	if groupBy == GroupNone || groupBy == "" {
		rows := make([]groupedRow, 0, len(certificates))
		for _, certificate := range certificates {
			rows = append(rows, groupedRow{certificate: certificate})
		}
		return rows
	}
	groups := map[string][]inventory.Certificate{}
	order := []string{}
	for _, certificate := range certificates {
		key := groupKey(certificate, groupBy)
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], certificate)
	}
	sort.Strings(order)
	rows := make([]groupedRow, 0, len(certificates))
	for _, key := range order {
		label := "GROUP " + groupBy + ": " + key
		for index, certificate := range groups[key] {
			row := groupedRow{certificate: certificate}
			if index == 0 {
				row.header = label
			}
			rows = append(rows, row)
		}
	}
	return rows
}

func groupKey(certificate inventory.Certificate, groupBy string) string {
	if groupBy == GroupOwner {
		if len(certificate.Owners) == 0 {
			return "(unowned)"
		}
		return certificate.Owners[0].Value
	}
	if len(certificate.Names) == 0 {
		return "-"
	}
	return certificate.Names[0]
}

func displayEffective(value string) string {
	if value == "" {
		return "-"
	}
	return value
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
