// Package render owns stable output encodings.
package render

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/diag"
)

// CTDocument is the stable scadenza.ct/v1 JSON envelope.
type CTDocument struct {
	SchemaVersion string            `json:"schema_version"`
	Domain        string            `json:"domain"`
	GeneratedAt   time.Time         `json:"generated_at"`
	SourcesUsed   []string          `json:"sources_used"`
	Certificates  []ct.Certificate  `json:"certificates"`
	Diagnostics   []diag.Diagnostic `json:"diagnostics"`
}

// CT writes a CT document as table, JSON, or CSV.
func CT(writer io.Writer, format string, document CTDocument) error {
	switch format {
	case "json":
		document.SourcesUsed = emptyIfNil(document.SourcesUsed)
		document.Certificates = emptyIfNil(document.Certificates)
		document.Diagnostics = emptyIfNil(document.Diagnostics)
		for index := range document.Certificates {
			document.Certificates[index].SubjectNames = emptyIfNil(document.Certificates[index].SubjectNames)
		}
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(document)
	case "csv":
		return writeCSV(writer, document.Certificates)
	case "table":
		return writeTable(writer, document.Certificates)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func writeCSV(writer io.Writer, certificates []ct.Certificate) error {
	output := csv.NewWriter(writer)
	if err := output.Write([]string{"fingerprint_sha256", "serial", "subject_names", "issuer", "not_before", "not_after", "lifetime_days", "verdict_100d", "revoked", "source"}); err != nil {
		return err
	}
	for _, certificate := range certificates {
		revoked := ""
		if certificate.Revoked != nil {
			revoked = fmt.Sprint(*certificate.Revoked)
		}
		if err := output.Write([]string{csvSafe(certificate.Fingerprint), csvSafe(certificate.Serial), csvSafe(strings.Join(certificate.SubjectNames, " ")), csvSafe(certificate.Issuer), certificate.NotBefore.Format(time.RFC3339), certificate.NotAfter.Format(time.RFC3339), fmt.Sprint(certificate.LifetimeDays), certificate.Verdict100D, revoked, csvSafe(certificate.Source)}); err != nil {
			return err
		}
	}
	output.Flush()
	return output.Error()
}

// csvSafe neutralizes spreadsheet formula injection by prefixing a single quote.
func csvSafe(value string) string {
	if value != "" && strings.ContainsRune("=+-@	", rune(value[0])) {
		return "'" + value
	}
	return value
}

func writeTable(writer io.Writer, certificates []ct.Certificate) error {
	table := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "NOT BEFORE\tNOT AFTER\tDAYS\t100D\tFINGERPRINT SHA256\tSERIAL\tREVOKED\tISSUER\tNAMES\tSOURCE"); err != nil {
		return err
	}
	for _, certificate := range certificates {
		revoked := "-"
		if certificate.Revoked != nil {
			revoked = fmt.Sprint(*certificate.Revoked)
		}
		if _, err := fmt.Fprintf(table, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			certificate.NotBefore.Format("2006-01-02"),
			certificate.NotAfter.Format("2006-01-02"),
			certificate.LifetimeDays,
			sanitizeCell(certificate.Verdict100D),
			sanitizeCell(certificate.Fingerprint),
			sanitizeCell(certificate.Serial),
			revoked,
			sanitizeCell(certificate.Issuer),
			sanitizeCell(displayNames(certificate.SubjectNames)),
			sanitizeCell(certificate.Source),
		); err != nil {
			return err
		}
	}
	return table.Flush()
}

func displayNames(names []string) string {
	const visible = 3
	if len(names) <= visible {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:visible], ", ") + fmt.Sprintf(" +%d more", len(names)-visible)
}
