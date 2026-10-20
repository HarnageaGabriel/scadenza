package render

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

// tail returns the last runes of a value, so an error message shows where a
// cut value ends without printing a whole cell.
func tail(value string) string {
	runes := []rune(value)
	const keep = 8
	if len(runes) <= keep {
		return value
	}
	return string(runes[len(runes)-keep:])
}

// TestMaxCellRunesConstantAndCellCap pins the cell cap promise: the threat
// model caps a table or CSV cell at 256 characters, and a cell that is cut
// short is marked with an ellipsis.
func TestMaxCellRunesConstantAndCellCap(t *testing.T) {
	// Promise: MaxCellRunes is the exported cap of a table or CSV cell.
	if MaxCellRunes != 256 {
		t.Fatalf("MaxCellRunes = %d, want 256", MaxCellRunes)
	}
	for _, test := range []struct {
		name         string
		value        string
		want         string
		wantEllipsis bool
	}{
		// Promise: a value that is exactly at the cap is kept whole, with no
		// ellipsis, and still has exactly 256 characters.
		{"exactly at the cap", strings.Repeat("a", 256), strings.Repeat("a", 256), false},
		// Promise: a value one character over the cap is cut to exactly 256
		// characters and ends with the ellipsis.
		{"one character over the cap", strings.Repeat("a", 257), strings.Repeat("a", 255) + ellipsis, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cell := sanitizeCell(test.value)
			if count := utf8.RuneCountInString(cell); count != MaxCellRunes {
				t.Errorf("cell has %d runes, want %d", count, MaxCellRunes)
			}
			if cell != test.want {
				t.Errorf("cell = %d runes ending with %q, want %d runes ending with %q", utf8.RuneCountInString(cell), tail(cell), utf8.RuneCountInString(test.want), tail(test.want))
			}
			if got := strings.Contains(cell, ellipsis); got != test.wantEllipsis {
				t.Errorf("cell contains an ellipsis = %t, want %t", got, test.wantEllipsis)
			}
			if got := strings.HasSuffix(cell, ellipsis); got != test.wantEllipsis {
				t.Errorf("cell ends with an ellipsis = %t, want %t", got, test.wantEllipsis)
			}
		})
	}
}

// TestCapRunesBoundary pins the boundary of the cap: a value exactly at the
// limit is returned unchanged, and a value one rune over the limit is cut to
// limit-1 runes plus the ellipsis, so the result never exceeds the limit.
func TestCapRunesBoundary(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		limit int
		want  string
	}{
		{"exactly at the limit", strings.Repeat("a", 256), 256, strings.Repeat("a", 256)},
		{"one rune over the limit", strings.Repeat("a", 257), 256, strings.Repeat("a", 255) + ellipsis},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := capRunes(test.value, test.limit)
			if got != test.want {
				t.Errorf("capRunes(%d runes, %d) = %d runes ending with %q, want %d runes ending with %q", utf8.RuneCountInString(test.value), test.limit, utf8.RuneCountInString(got), tail(got), utf8.RuneCountInString(test.want), tail(test.want))
			}
			if count := utf8.RuneCountInString(got); count > test.limit {
				t.Errorf("capRunes returned %d runes, want at most %d", count, test.limit)
			}
		})
	}
}

// TestSafeTextRemovesLineAndParagraphSeparators pins the promise that the
// line separator U+2028 and the paragraph separator U+2029 are removed, so
// an untrusted value can never break out of the line it is rendered into.
func TestSafeTextRemovesLineAndParagraphSeparators(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		want  string
	}{
		{"line separator", "a\u2028b", "ab"},
		{"paragraph separator", "a\u2029b", "ab"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := SafeText(test.value); got != test.want {
				t.Errorf("SafeText(%q) = %q, want %q", test.value, got, test.want)
			}
		})
	}

	// Promise: a table is printed literally, so a rendered table cell and a
	// CSV cell never carry a line or a paragraph separator.
	value := "a\u2028b\u2029c"
	for _, format := range []string{"table", "csv"} {
		t.Run(format, func(t *testing.T) {
			var output bytes.Buffer
			if err := CT(&output, format, hostileCTDocument(value)); err != nil {
				t.Fatal(err)
			}
			rendered := output.String()
			for _, separator := range []rune{'\u2028', '\u2029'} {
				if strings.ContainsRune(rendered, separator) {
					t.Errorf("%s output carries the separator %U", format, separator)
				}
			}
			assertNoHostileRunes(t, rendered)
		})
	}
}

// TestCSVSafeLooksPastLeadingWhitespace pins the formula guard promise: a
// cell that starts with a formula character, also after leading whitespace
// such as a non breaking space, is prefixed with a single quote.
func TestCSVSafeLooksPastLeadingWhitespace(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		want  string
	}{
		// Promise: the guard looks past a non breaking space, so the cell is
		// quoted instead of being evaluated as a formula.
		{"non breaking space then equals", "\u00A0=1+1", "'\u00A0=1+1"},
		// Promise: the guard looks past an ideographic space as well.
		{"ideographic space then equals", "\u3000=1+1", "'\u3000=1+1"},
		// Promise: the guard looks past leading spaces, so the cell is
		// quoted instead of being evaluated as a formula.
		{"spaces then plus", "   +1+1", "'   +1+1"},
		// Promise: a value that is not a formula is left alone.
		{"plain value", "plain", "plain"},
		{"empty value", "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := csvSafe(test.value); got != test.want {
				t.Errorf("csvSafe(%q) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}
