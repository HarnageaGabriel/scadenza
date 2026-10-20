package render

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxCellRunes caps a rendered table or CSV cell at 256 display columns.
	// Long values are cut and marked with an ellipsis so one hostile name
	// cannot flood the output and cannot wrap the terminal.
	//
	// The name keeps the rune wording, but the cap counts the columns a
	// terminal spends on the value: a fullwidth character takes two columns,
	// so a cell of 199 of them takes 398 and wraps the line.
	MaxCellRunes = 256
	// MaxDetailRunes caps an untrusted detail written to stderr, in display
	// columns.
	MaxDetailRunes = 512
)

// ellipsis marks a value that was cut short.
const ellipsis = "…"

// wideRuneRange is one inclusive range of code points that take two
// terminal columns.
type wideRuneRange struct {
	low  rune
	high rune
}

// wideRuneRanges are the code points that take two terminal columns: the
// East Asian wide and fullwidth characters and the emoji. The table is
// deliberately small and local, so the render package keeps its promise
// without taking on a dependency.
var wideRuneRanges = []wideRuneRange{
	{0x1100, 0x115F},   // Hangul Jamo
	{0x2E80, 0x303E},   // CJK radicals and symbols
	{0x3041, 0x33FF},   // Hiragana through CJK compatibility
	{0x3400, 0x4DBF},   // CJK unified ideographs extension A
	{0x4E00, 0x9FFF},   // CJK unified ideographs
	{0xAC00, 0xD7A3},   // Hangul syllables
	{0xF900, 0xFAFF},   // CJK compatibility ideographs
	{0xFE30, 0xFE6F},   // vertical and small forms
	{0xFF01, 0xFF60},   // fullwidth forms
	{0xFFE0, 0xFFE6},   // fullwidth signs
	{0x1F300, 0x1F64F}, // emoji
	{0x1F900, 0x1F9FF}, // supplemental symbols and pictographs
	{0x1FA70, 0x1FAFF}, // extended-A symbols
	{0x20000, 0x3FFFD}, // supplementary ideographic plane
}

// emptyIfNil keeps JSON arrays non-null.
func emptyIfNil[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}

// SafeText cleans an untrusted value for display. It drops the characters that
// can forge a log line or attack a terminal, turns tabs and line breaks into
// a single space, and caps the result at MaxDetailRunes display columns.
//
// The cli package reuses it for stderr, so the table, the CSV, and the
// diagnostic lines share one rule.
func SafeText(value string) string {
	return capRunes(cleanText(value), MaxDetailRunes)
}

// cleanText removes the characters that can hide their presence or forge a
// log line: control characters (category Cc), format characters (category
// Cf, such as the zero width space, the left to right and right to left
// marks, the embedding and override characters, the isolates, and the byte
// order mark), private use characters (category Co), and unassigned code
// points (category Cn, to which no category letter applies), plus the line
// and paragraph separators, the Hangul fillers, the combining grapheme
// joiner, the Mongolian free variation selectors and vowel separator, and the
// variation selectors supplement. Tabs, newlines, and carriage returns
// become a single space, so a value can never break out of its line.
//
// The other combining marks stay, including the ordinary variation selectors
// U+FE00 to U+FE0F, because real scripts and emoji need them.
//
// JSON escapes its own control characters and CSV quotes them, but a table is
// printed literally and a diagnostic line is read literally.
func cleanText(value string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			return ' '
		case unicode.IsControl(r):
			return -1
		case unicode.Is(unicode.Cf, r):
			return -1
		case unicode.Is(unicode.Co, r):
			return -1
		case unicode.Is(unicode.Cn, r):
			return -1
		case r == '\u2028' || r == '\u2029':
			return -1
		// The Hangul fillers take up the width of a syllable but draw no
		// glyph, so they only pad a name out of shape.
		case r == '\u115F' || r == '\u1160' || r == '\u3164' || r == '\uFFA0':
			return -1
		// The combining grapheme joiner, the Mongolian free variation
		// selectors and vowel separator, and the variation selectors
		// supplement draw no glyph. The ordinary variation selectors
		// U+FE00 to U+FE0F are not in this set, because real scripts and
		// emoji need them.
		case r == '\u034F':
			return -1
		case r >= '\u180B' && r <= '\u180E':
			return -1
		case r >= '\U000E0100' && r <= '\U000E01EF':
			return -1
		}
		return r
	}, value)
}

// runeWidth returns the number of terminal columns a rune takes: 0 for a
// combining mark, 2 for an East Asian wide or fullwidth character and for an
// emoji, and 1 for everything else.
func runeWidth(r rune) int {
	switch {
	case r < 0x0300:
		return 1
	case r <= 0xE01EF && unicode.In(r, unicode.Mn, unicode.Me):
		return 0
	}
	for _, wide := range wideRuneRanges {
		if r < wide.low {
			return 1
		}
		if r <= wide.high {
			return 2
		}
	}
	return 1
}

// displayWidth returns the number of terminal columns a value takes.
func displayWidth(value string) int {
	width := 0
	for _, r := range value {
		width += runeWidth(r)
	}
	return width
}

// capRunes cuts a value to at most limit display columns and marks the cut
// with an ellipsis, so the result never exceeds the limit.
//
// The cap counts columns, not runes: a fullwidth character takes two columns,
// so a cell of 199 of them takes 398 and wraps the terminal, and a wrapped
// visual line can start with text an attacker chose. A cut never splits a
// wide character, so the result can be one column short of the limit.
func capRunes(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	width := 0
	count := 0
	for _, r := range value {
		width += runeWidth(r)
		count++
		// Combining marks take no column, so the rune count is bounded too:
		// a value made only of marks must not escape the cap.
		if width > limit || count > limit*maxRunesPerColumn {
			return value[:cutColumns(value, limit-1)] + ellipsis
		}
	}
	return value
}

// maxRunesPerColumn bounds how many runes a capped value may hold per column
// of its cap. Real text needs at most a few combining marks per base
// character; more is an attempt to avoid the column count.
const maxRunesPerColumn = 4

// cutColumns returns the length in bytes of the longest prefix of value whose
// display width is at most columns. A wide character that would exceed the
// budget ends the prefix, so a cut never splits it.
func cutColumns(value string, columns int) int {
	width := 0
	kept := 0
	count := 0
	for index, r := range value {
		w := runeWidth(r)
		count++
		if width+w > columns || count > columns*maxRunesPerColumn {
			break
		}
		width += w
		kept = index + utf8.RuneLen(r)
	}
	return kept
}

// sanitizeCell removes the characters that can forge a log line or attack a
// terminal from an untrusted value, and caps the cell, before it reaches a
// terminal-oriented table.
func sanitizeCell(value string) string {
	return capRunes(SafeText(value), MaxCellRunes)
}
