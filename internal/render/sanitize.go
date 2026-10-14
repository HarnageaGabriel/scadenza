package render

import (
	"strings"
	"unicode"
)

func emptyIfNil[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}

// sanitizeCell removes control characters, including ESC and newlines, from an
// untrusted value before it reaches a terminal-oriented table. JSON escapes its
// own control characters and CSV quotes them, but a table is printed literally.
func sanitizeCell(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value)
}
