package render

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/inventory"
	"github.com/HarnageaGabriel/scadenza/internal/owner"
)

// hostileValue is one untrusted value that must never break out of the cell,
// the record, or the line it is rendered into.
type hostileValue struct {
	name  string
	value string
}

// hostileValues are the values a hostile Certificate Transparency log, a
// hostile cluster, or a hostile Key Vault can put into a name, a label, a
// tag, or an owner.
var hostileValues = []hostileValue{
	{"ansi colour", "\x1b[31mred\x1b[0m"},
	{"right to left override", "evil\u202Egnp.exe"},
	{"zero width space", "zero\u200Bwidth.example.com"},
	{"newline then pass", "evil.example.com\nPASS"},
	{"workflow command", "::error::forged"},
	{"hash pair", "## forged"},
	{"formula", "=1+1"},
	{"newline then formula", "\n=1+1"},
	{"spaces then formula", "   =1+1"},
	{"one mebibyte", strings.Repeat("a", 1<<20)},
}

// assertNoHostileRunes fails when a rendered output carries a control
// character, a format character, or a line or paragraph separator on any of
// its lines.
func assertNoHostileRunes(t *testing.T, output string) {
	t.Helper()
	for number, line := range strings.Split(output, "\n") {
		for _, r := range line {
			switch {
			case unicode.IsControl(r):
				t.Errorf("line %d carries the control character %U", number+1, r)
			case unicode.Is(unicode.Cf, r):
				t.Errorf("line %d carries the format character %U", number+1, r)
			case r == '\u2028' || r == '\u2029':
				t.Errorf("line %d carries the separator %U", number+1, r)
			}
		}
	}
}

// assertSingleLineRecords fails when the raw CSV output does not hold exactly
// one physical line per record.
func assertSingleLineRecords(t *testing.T, raw string, records int) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
	if len(lines) != records {
		t.Fatalf("csv output has %d physical lines, want %d:\n%s", len(lines), records, raw)
	}
}

func TestSafeTextRemovesHostileCharacters(t *testing.T) {
	for _, hostile := range hostileValues {
		t.Run(hostile.name, func(t *testing.T) {
			cleaned := SafeText(hostile.value)
			assertNoHostileRunes(t, cleaned)
			if strings.ContainsAny(cleaned, "\n\r") {
				t.Errorf("cleaned value carries a line break: %q", cleaned)
			}
			if count := utf8.RuneCountInString(cleaned); count > MaxDetailRunes {
				t.Errorf("cleaned value has %d runes, want at most %d", count, MaxDetailRunes)
			}
		})
	}
}

func TestSafeTextTurnsLineBreaksIntoSpaces(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		want  string
	}{
		{"newline", "a\nb", "a b"},
		{"carriage return", "a\rb", "a b"},
		{"tab", "a\tb", "a b"},
		{"carriage return and newline", "a\r\nb", "a  b"},
		{"empty", "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := SafeText(test.value); got != test.want {
				t.Errorf("SafeText(%q) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}

func TestSanitizeCellCapsLength(t *testing.T) {
	for _, hostile := range hostileValues {
		t.Run(hostile.name, func(t *testing.T) {
			cell := sanitizeCell(hostile.value)
			if count := utf8.RuneCountInString(cell); count > MaxCellRunes {
				t.Errorf("cell has %d runes, want at most %d", count, MaxCellRunes)
			}
			if count := utf8.RuneCountInString(hostile.value); count > MaxCellRunes && !strings.HasSuffix(cell, ellipsis) {
				t.Errorf("cell %q does not end with an ellipsis", cell)
			}
		})
	}
}

// assertBoundedLines fails when a rendered table line is longer than the
// widest possible cell plus its padding, which no cell may exceed.
func assertBoundedLines(t *testing.T, output string) {
	t.Helper()
	const bound = 16 * (MaxCellRunes + 2)
	for number, line := range strings.Split(output, "\n") {
		if count := utf8.RuneCountInString(line); count > bound {
			t.Errorf("line %d has %d runes, want at most %d", number+1, count, bound)
		}
	}
}

func TestCTTableNeutralizesHostileValues(t *testing.T) {
	for _, hostile := range hostileValues {
		t.Run(hostile.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := CT(&output, "table", hostileCTDocument(hostile.value)); err != nil {
				t.Fatal(err)
			}
			rendered := output.String()
			assertNoHostileRunes(t, rendered)
			assertBoundedLines(t, rendered)
			want := sanitizeCell(hostile.value)
			if !strings.Contains(rendered, want) {
				t.Errorf("table output is missing the sanitized cell %q:\n%s", want, rendered)
			}
			if want != hostile.value && strings.Contains(rendered, hostile.value) {
				t.Errorf("table output carries the untrusted value:\n%s", rendered)
			}
		})
	}
}

func TestCTCSVRecordsAreOnePhysicalLine(t *testing.T) {
	for _, hostile := range hostileValues {
		t.Run(hostile.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := CT(&output, "csv", hostileCTDocument(hostile.value)); err != nil {
				t.Fatal(err)
			}
			raw := output.String()
			assertNoHostileRunes(t, raw)
			assertSingleLineRecords(t, raw, 2)
			rows, err := csv.NewReader(strings.NewReader(raw)).ReadAll()
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 2 {
				t.Fatalf("csv records = %d, want 2", len(rows))
			}
			for index, cell := range rows[1] {
				if count := utf8.RuneCountInString(cell); count > MaxCellRunes {
					t.Errorf("cell %d has %d runes, want at most %d", index, count, MaxCellRunes)
				}
			}
		})
	}
}

func TestCTJSONKeepsTheFullValue(t *testing.T) {
	for _, hostile := range hostileValues {
		t.Run(hostile.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := CT(&output, "json", hostileCTDocument(hostile.value)); err != nil {
				t.Fatal(err)
			}
			var document CTDocument
			if err := json.Unmarshal(output.Bytes(), &document); err != nil {
				t.Fatal(err)
			}
			if len(document.Certificates) != 1 {
				t.Fatalf("json certificates = %d, want 1", len(document.Certificates))
			}
			certificate := document.Certificates[0]
			if len(certificate.SubjectNames) != 1 || certificate.SubjectNames[0] != hostile.value {
				t.Errorf("json subject names = %q, want the full value", certificate.SubjectNames)
			}
			if certificate.Issuer != hostile.value {
				t.Errorf("json issuer = %q, want the full value", certificate.Issuer)
			}
			escaped, err := json.Marshal(hostile.value)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), string(escaped)) {
				t.Errorf("json output does not carry the escaped value %s", escaped)
			}
		})
	}
}

func TestScanTableNeutralizesHostileValues(t *testing.T) {
	for _, hostile := range hostileValues {
		t.Run(hostile.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := Scan(&output, "table", hostileScanDocument(hostile.value)); err != nil {
				t.Fatal(err)
			}
			rendered := output.String()
			assertNoHostileRunes(t, rendered)
			assertBoundedLines(t, rendered)
			want := sanitizeCell(hostile.value)
			if !strings.Contains(rendered, want) {
				t.Errorf("table output is missing the sanitized cell %q:\n%s", want, rendered)
			}
			if want != hostile.value && strings.Contains(rendered, hostile.value) {
				t.Errorf("table output carries the untrusted value:\n%s", rendered)
			}
		})
	}
}

func TestScanCSVRecordsAreOnePhysicalLine(t *testing.T) {
	for _, hostile := range hostileValues {
		t.Run(hostile.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := Scan(&output, "csv", hostileScanDocument(hostile.value)); err != nil {
				t.Fatal(err)
			}
			raw := output.String()
			assertNoHostileRunes(t, raw)
			assertSingleLineRecords(t, raw, 2)
			rows, err := csv.NewReader(strings.NewReader(raw)).ReadAll()
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 2 {
				t.Fatalf("csv records = %d, want 2", len(rows))
			}
			for index, cell := range rows[1] {
				if count := utf8.RuneCountInString(cell); count > MaxCellRunes {
					t.Errorf("cell %d has %d runes, want at most %d", index, count, MaxCellRunes)
				}
			}
		})
	}
}

func TestScanJSONKeepsTheFullValue(t *testing.T) {
	for _, hostile := range hostileValues {
		t.Run(hostile.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := Scan(&output, "json", hostileScanDocument(hostile.value)); err != nil {
				t.Fatal(err)
			}
			escaped, err := json.Marshal(hostile.value)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), string(escaped)) {
				t.Errorf("json output does not carry the escaped value %s", escaped)
			}
		})
	}
}

// hostileCTDocument puts one hostile value into every untrusted certificate
// field the CT output renders.
func hostileCTDocument(value string) CTDocument {
	revoked := false
	certificate := ct.Certificate{
		Fingerprint:  value,
		Serial:       value,
		SubjectNames: []string{value},
		Issuer:       value,
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		LifetimeDays: 90,
		Verdict100D:  value,
		Revoked:      &revoked,
		Source:       value,
	}
	return CTDocument{
		SchemaVersion: "scadenza.ct/v1",
		Domain:        "example.com",
		GeneratedAt:   certificate.NotBefore,
		SourcesUsed:   []string{"test"},
		Certificates:  []ct.Certificate{certificate},
	}
}

// hostileScanDocument puts one hostile value into every untrusted field the
// scan output renders: names, issuer, observations, owners, findings, and
// unresolved names.
func hostileScanDocument(value string) ScanDocument {
	yes := true
	return ScanDocument{
		SchemaVersion: "scadenza.scan/v1",
		GeneratedAt:   time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		Domains:       []string{"example.com"},
		SourcesUsed:   []string{"certspotter"},
		Certificates: []inventory.Certificate{{
			Fingerprint: value,
			Serial:      value,
			Names:       []string{value},
			Issuer:      value,
			NotBefore:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:    time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
			Verdict100D: value,
			Public:      &yes,
			Observations: []inventory.Observation{{
				Source:   inventory.SourceCertSpotter,
				Location: value,
				Detail:   value,
			}},
			Owners: []owner.Owner{{Value: value, Source: owner.SourceLabel, Location: value}},
		}},
		Findings: []inventory.Finding{{
			Kind:        inventory.KindCTOnly,
			Fingerprint: value,
			Names:       []string{value},
			Detail:      value,
		}},
		Unresolved: []inventory.Unresolved{{Name: value, Reason: "wildcard", Detail: value}},
	}
}
