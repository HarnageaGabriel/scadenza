// Package render owns stable output encodings.
package render

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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
		// JSON is data, not display: it must carry the exact values a consumer
		// reads back, so it is never truncated or sanitized. HTML escaping stays
		// off because a JSON consumer is not a browser, and escaping would
		// rewrite legitimate characters such as <, >, and &. The encoder always
		// escapes control characters itself, so the output stays one valid
		// document.
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
		// Every text cell is sanitized first, so a record is always exactly one
		// physical line, and then guarded against formula injection.
		if err := output.Write([]string{csvCell(certificate.Fingerprint), csvCell(certificate.Serial), csvCell(strings.Join(certificate.SubjectNames, " ")), csvCell(certificate.Issuer), certificate.NotBefore.Format(time.RFC3339), certificate.NotAfter.Format(time.RFC3339), fmt.Sprint(certificate.LifetimeDays), csvCell(certificate.Verdict100D), csvCell(revoked), csvCell(certificate.Source)}); err != nil {
			return err
		}
	}
	output.Flush()
	return output.Error()
}

// csvCell sanitizes an untrusted value and neutralizes spreadsheet formula
// injection in it, so a cell is one physical line, cannot be a formula, and
// stays within the cell cap.
func csvCell(value string) string {
	return capRunes(csvSafe(sanitizeCell(value)), MaxCellRunes)
}

// csvFormulaLookalikes are the Unicode code points that look like the ASCII
// formula characters: the fullwidth forms of equals, plus, hyphen minus and
// commercial at, and the small forms of the same four.
//
// VERIFY: spreadsheets are not confirmed to treat these lookalikes as
// formulas, so the guard quotes them anyway. The caution is deliberate:
// quoting a cell that was never a formula costs a single apostrophe, while
// missing a lookalike lets a spreadsheet evaluate a formula.
const csvFormulaLookalikes = "\uFF1D\uFF0B\uFF0D\uFF20\uFE66\uFE62\uFE63\uFE6B"

// csvSafe neutralizes spreadsheet formula injection by prefixing a single
// quote. The value is sanitized before it gets here, so it can no longer
// contain a line break; the guard still covers a value that starts with a tab
// or a carriage return, and it looks past leading whitespace, so a cell that
// starts with spaces or a non breaking space before a formula character is
// guarded as well. The Unicode lookalikes of the formula characters are
// guarded the same way, so a cell that starts with a fullwidth or small form
// of equals, plus, hyphen minus or commercial at is quoted too.
func csvSafe(value string) string {
	if value == "" {
		return value
	}
	first, _ := utf8.DecodeRuneInString(value)
	if strings.ContainsRune("=+-@\t\r", first) || strings.ContainsRune(csvFormulaLookalikes, first) {
		return "'" + value
	}
	trimmed := strings.TrimLeftFunc(value, unicode.IsSpace)
	if trimmed == "" {
		return value
	}
	leading, _ := utf8.DecodeRuneInString(trimmed)
	if strings.ContainsRune("=+-@", leading) || strings.ContainsRune(csvFormulaLookalikes, leading) {
		return "'" + value
	}
	return value
}

func writeTable(writer io.Writer, certificates []ct.Certificate) error {
	table := newTableWriter(writer)
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
			sanitizeCell(revoked),
			sanitizeCell(certificate.Issuer),
			sanitizeCell(displayNames(certificate.SubjectNames)),
			sanitizeCell(certificate.Source),
		); err != nil {
			return err
		}
	}
	return table.Flush()
}

// tableWriter aligns tab-separated cells by terminal display width.
// text/tabwriter pads by rune count, so a fullwidth or emoji cell shifts
// every column after it; padding by displayWidth keeps the columns aligned.
type tableWriter struct {
	writer io.Writer
	buf    bytes.Buffer
}

func newTableWriter(writer io.Writer) *tableWriter {
	return &tableWriter{writer: writer}
}

func (t *tableWriter) Write(p []byte) (int, error) {
	return t.buf.Write(p)
}

// Flush writes the buffered lines, padding each column to its widest cell
// plus two spaces, the layout text/tabwriter produced for ASCII tables.
// Single-cell lines (section and group headers) pass through untouched and
// start a new column block, as tabwriter did.
func (t *tableWriter) Flush() error {
	text := t.buf.String()
	t.buf.Reset()
	if text == "" {
		return nil
	}
	var block [][]string
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		cells := strings.Split(line, "\t")
		if len(cells) == 1 {
			if err := t.flushBlock(block); err != nil {
				return err
			}
			block = nil
			if _, err := fmt.Fprintln(t.writer, line); err != nil {
				return err
			}
			continue
		}
		block = append(block, cells)
	}
	return t.flushBlock(block)
}

func (t *tableWriter) flushBlock(block [][]string) error {
	widths := make([]int, 0)
	for _, cells := range block {
		for column := 0; column < len(cells)-1; column++ {
			for len(widths) <= column {
				widths = append(widths, 0)
			}
			if width := displayWidth(cells[column]) + 2; width > widths[column] {
				widths[column] = width
			}
		}
	}
	for _, cells := range block {
		for column, cell := range cells {
			if _, err := io.WriteString(t.writer, cell); err != nil {
				return err
			}
			if column < len(cells)-1 {
				if _, err := io.WriteString(t.writer, strings.Repeat(" ", widths[column]-displayWidth(cell))); err != nil {
					return err
				}
			}
		}
		if _, err := io.WriteString(t.writer, "\n"); err != nil {
			return err
		}
	}
	return nil
}

func displayNames(names []string) string {
	const visible = 3
	if len(names) <= visible {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:visible], ", ") + fmt.Sprintf(" +%d more", len(names)-visible)
}
