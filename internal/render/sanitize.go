package render

import (
	"strings"
	"unicode"
)

const (
	// MaxCellRunes caps a rendered table or CSV cell. Long values are cut and
	// marked with an ellipsis so one hostile name cannot flood the output.
	MaxCellRunes = 256
	// MaxDetailRunes caps an untrusted detail written to stderr.
	MaxDetailRunes = 512
)

// ellipsis marks a value that was cut short.
const ellipsis = "…"

// emptyIfNil keeps JSON arrays non-null.
func emptyIfNil[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}

// SafeText cleans an untrusted value for display. It drops the characters that
// can forge a log line or attack a terminal, turns tabs and line breaks into
// a single space, and caps the result at MaxDetailRunes runes.
//
// The cli package reuses it for stderr, so the table, the CSV, and the
// diagnostic lines share one rule.
func SafeText(value string) string {
	return capRunes(cleanText(value), MaxDetailRunes)
}

// cleanText removes control characters (category Cc) and format characters
// (category Cf, such as the zero width space, the left to right and right to
// left marks, the embedding and override characters, the isolates, and the
// byte order mark), plus the line and paragraph separators. Tabs, newlines,
// and carriage returns become a single space, so a value can never break out
// of its line.
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
		case r == '\u2028' || r == '\u2029':
			return -1
		}
		return r
	}, value)
}

// capRunes cuts a value to at most limit runes and marks the cut with an
// ellipsis, so the result never exceeds the limit.
func capRunes(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit-1]) + ellipsis
}

// sanitizeCell removes the characters that can forge a log line or attack a
// terminal from an untrusted value, and caps the cell, before it reaches a
// terminal-oriented table.
func sanitizeCell(value string) string {
	return capRunes(SafeText(value), MaxCellRunes)
}
