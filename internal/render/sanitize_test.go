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
// model caps a table or CSV cell at 256 display columns, and a cell that is
// cut short is marked with an ellipsis.
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

// TestRuneWidth pins the display width of a rune: a combining mark takes no
// column, a wide or fullwidth character and an emoji take two, and anything
// else takes one. The table is the render package's own, so the promise is
// pinned here instead of in a dependency.
func TestRuneWidth(t *testing.T) {
	for _, test := range []struct {
		name string
		r    rune
		want int
	}{
		{"ascii letter", 'a', 1},
		{"digit", '7', 1},
		{"latin accent", 'é', 1},
		{"greek omega", 'Ω', 1},
		{"arabic letter", 'ب', 1},
		{"combining acute accent", '́', 0},
		{"combining enclosing keycap", '⃣', 0},
		{"hangul jamo lead", 'ᄀ', 2},
		{"hangul jamo tail", 'ᅟ', 2},
		{"cjk radical", '⺀', 2},
		{"cjk symbol", '〾', 2},
		{"hiragana", 'ぁ', 2},
		{"katakana", 'ァ', 2},
		{"cjk compatibility end", '㏿', 2},
		{"ideograph extension a", '㐀', 2},
		{"ideograph extension a end", '䶿', 2},
		{"ideograph", '一', 2},
		{"ideograph end", '鿿', 2},
		{"hangul syllable", '가', 2},
		{"hangul syllable end", '힣', 2},
		{"cjk compatibility ideograph", '豈', 2},
		{"cjk compatibility ideograph end", '﫿', 2},
		{"vertical form", '︰', 2},
		{"small form end", '﹯', 2},
		{"fullwidth exclamation", '！', 2},
		{"fullwidth end", '｠', 2},
		{"fullwidth currency", '￠', 2},
		{"fullwidth sign end", '￦', 2},
		{"emoji", '\U0001F300', 2},
		{"emoji end", '\U0001F64F', 2},
		{"supplemental symbol", '\U0001F900', 2},
		{"supplemental symbol end", '\U0001F9FF', 2},
		{"extended a symbol", '\U0001FA70', 2},
		{"extended a symbol end", '\U0001FAFF', 2},
		{"supplementary ideograph", '\U00020000', 2},
		{"supplementary ideograph end", '\U0003FFFD', 2},
		// Promise: the code points just outside a range stay narrow, so the
		// table does not claim more columns than a terminal spends.
		{"after the hangul jamo", '\u1160', 1},
		{"before the cjk radicals", '\u2E7F', 1},
		{"after the cjk symbols", '\u303F', 1},
		{"before the hiragana", '\u3040', 1},
		{"after the ideographs extension a", '\u4DC0', 1},
		{"after the ideographs", '\uA000', 1},
		{"after the hangul syllables", '\uD7A4', 1},
		{"after the cjk compatibility ideographs", '\uFB00', 1},
		{"after the small forms", '\uFE70', 1},
		{"halfwidth katakana", '\uFF61', 1},
		{"after the fullwidth signs", '\uFFE7', 1},
		{"after the emoji", '\U0001F650', 1},
		{"after the supplemental symbols", '\U0001FA00', 1},
		{"after the extended a symbols", '\U0001FB00', 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := runeWidth(test.r); got != test.want {
				t.Errorf("runeWidth(%U) = %d, want %d", test.r, got, test.want)
			}
		})
	}
}

// TestCapRunesCountsDisplayColumns pins the cap promise in the unit that
// matters on a terminal: the cap counts the columns a value takes, not its
// runes. A value of fullwidth characters is cut before it can wrap the line,
// and a cut never splits a wide character.
func TestCapRunesCountsDisplayColumns(t *testing.T) {
	const wide = "界"
	for _, test := range []struct {
		name      string
		value     string
		wantWidth int
		wantCut   bool
	}{
		// Promise: narrow text behaves exactly as before.
		{"narrow at the cap", strings.Repeat("a", 256), 256, false},
		{"narrow over the cap", strings.Repeat("a", 257), 256, true},
		// Promise: 128 fullwidth characters take 256 columns and stay whole.
		{"fullwidth at the cap", strings.Repeat(wide, 128), 256, false},
		// Promise: 129 fullwidth characters take 258 columns and are cut, and
		// the result never exceeds the cap.
		{"fullwidth over the cap", strings.Repeat(wide, 129), 255, true},
		// Promise: a flood of fullwidth characters is cut to the cap.
		{"fullwidth flood", strings.Repeat(wide, 199), 255, true},
		// Promise: a mix of narrow and wide characters is cut on the columns.
		{"mixed at the cap", strings.Repeat("a", 100) + strings.Repeat(wide, 78), 256, false},
		{"mixed over the cap", strings.Repeat("a", 100) + strings.Repeat(wide, 79), 255, true},
		// Promise: a combining mark takes no column, so it never pushes a
		// value over the cap.
		{"combining marks add no width", strings.Repeat("a"+"\u0301", 200), 200, false},
		{"combining marks over the cap", strings.Repeat("a"+"\u0301", 300), 256, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := capRunes(test.value, MaxCellRunes)
			if width := displayWidth(got); width != test.wantWidth {
				t.Errorf("capRunes returned %d columns, want %d", width, test.wantWidth)
			}
			if width := displayWidth(got); width > MaxCellRunes {
				t.Errorf("capRunes returned %d columns, want at most %d", width, MaxCellRunes)
			}
			if cut := strings.HasSuffix(got, ellipsis); cut != test.wantCut {
				t.Errorf("capRunes cut the value = %t, want %t", cut, test.wantCut)
			}
			// Promise: a cut keeps a prefix of the value, so it never splits
			// a wide character.
			if !strings.HasPrefix(test.value, strings.TrimSuffix(got, ellipsis)) {
				t.Errorf("capRunes did not keep a prefix of the value")
			}
		})
	}
}

// TestSanitizeCellCapsDisplayColumns pins the cell promise: a table or CSV
// cell never takes more than the cap in terminal columns, so it cannot make
// the terminal wrap a line the attacker chose.
func TestSanitizeCellCapsDisplayColumns(t *testing.T) {
	const wide = "界"
	for _, test := range []struct {
		name      string
		value     string
		wantWidth int
		wantCut   bool
	}{
		{"fullwidth at the cap", strings.Repeat(wide, 128), 256, false},
		{"fullwidth over the cap", strings.Repeat(wide, 129), 255, true},
		{"fullwidth flood", strings.Repeat(wide, 199), 255, true},
		{"narrow at the cap", strings.Repeat("a", 256), 256, false},
		{"narrow over the cap", strings.Repeat("a", 257), 256, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cell := sanitizeCell(test.value)
			if width := displayWidth(cell); width != test.wantWidth {
				t.Errorf("cell takes %d columns, want %d", width, test.wantWidth)
			}
			if width := displayWidth(cell); width > MaxCellRunes {
				t.Errorf("cell takes %d columns, want at most %d", width, MaxCellRunes)
			}
			if cut := strings.HasSuffix(cell, ellipsis); cut != test.wantCut {
				t.Errorf("cell was cut = %t, want %t", cut, test.wantCut)
			}
		})
	}
}

// TestCTTableStaysInsideTheColumnBound pins the end to end promise: a table
// that carries a flood of fullwidth characters stays inside the column bound,
// so the terminal does not wrap it and no wrapped line starts with text an
// attacker chose.
func TestCTTableStaysInsideTheColumnBound(t *testing.T) {
	const bound = 16 * (MaxCellRunes + 2)
	var output bytes.Buffer
	if err := CT(&output, "table", hostileCTDocument(strings.Repeat("界", 199))); err != nil {
		t.Fatal(err)
	}
	for number, line := range strings.Split(output.String(), "\n") {
		if width := displayWidth(line); width > bound {
			t.Errorf("line %d takes %d columns, want at most %d", number+1, width, bound)
		}
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

// A value made only of combining marks takes no column, so the column count
// alone would never cut it. The rune bound keeps it capped.
func TestCapRunesBoundsZeroWidthValues(t *testing.T) {
	marks := "a" + strings.Repeat("́", 1<<20)
	got := capRunes(marks, MaxCellRunes)
	if n := len([]rune(got)); n > MaxCellRunes*maxRunesPerColumn {
		t.Fatalf("zero width value kept %d runes, want at most %d", n, MaxCellRunes*maxRunesPerColumn)
	}
	if !strings.HasSuffix(got, ellipsis) {
		t.Fatalf("a cut value must end with the ellipsis")
	}
	// A normal accented word is untouched.
	if word := "café au lait"; capRunes(word, MaxCellRunes) != word {
		t.Fatalf("a normal value was cut")
	}
}

// TestCSVSafeQuotesUnicodeFormulaLookalikes pins the formula guard promise
// for the Unicode lookalikes of the formula characters: a cell that starts
// with a fullwidth or small form of equals, plus, hyphen minus or commercial
// at is prefixed with a single quote, also after leading whitespace such as a
// space or a non breaking space.
func TestCSVSafeQuotesUnicodeFormulaLookalikes(t *testing.T) {
	for _, lookalike := range []struct {
		name  string
		value string
	}{
		{"fullwidth equals", "\uFF1D"},
		{"fullwidth plus", "\uFF0B"},
		{"fullwidth hyphen minus", "\uFF0D"},
		{"fullwidth commercial at", "\uFF20"},
		{"small equals", "\uFE66"},
		{"small plus", "\uFE62"},
		{"small hyphen minus", "\uFE63"},
		{"small at", "\uFE6B"},
	} {
		for _, prefix := range []struct {
			name  string
			value string
		}{
			{"at the start", ""},
			{"after a space", " "},
			{"after a non breaking space", "\u00A0"},
		} {
			t.Run(lookalike.name+" "+prefix.name, func(t *testing.T) {
				// Promise: the lookalike is quoted, so the cell is not
				// evaluated as a formula.
				value := prefix.value + lookalike.value + "1+1"
				if got := csvSafe(value); got != "'"+value {
					t.Errorf("csvSafe(%q) = %q, want %q", value, got, "'"+value)
				}
			})
		}
	}
}

// TestCSVSafeLeavesLookalikesInsideAValueAlone pins the other side of the
// promise: a lookalike that appears later in the value is not a formula, and
// a value that starts with an ordinary letter is left alone.
func TestCSVSafeLeavesLookalikesInsideAValueAlone(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
	}{
		{"fullwidth equals inside", "a\uFF1D1+1"},
		{"fullwidth plus inside", "a\uFF0B1+1"},
		{"fullwidth hyphen minus inside", "a\uFF0D1+1"},
		{"fullwidth commercial at inside", "a\uFF201+1"},
		{"small equals inside", "a\uFE661+1"},
		{"small plus inside", "a\uFE621+1"},
		{"small hyphen minus inside", "a\uFE631+1"},
		{"small at inside", "a\uFE6B1+1"},
		{"letter then text", "a1+1"},
		{"plain value", "plain"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := csvSafe(test.value); got != test.value {
				t.Errorf("csvSafe(%q) = %q, want %q", test.value, got, test.value)
			}
		})
	}
}
