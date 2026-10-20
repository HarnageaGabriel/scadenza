package render

import (
	"bytes"
	"strings"
	"testing"
	"unicode"
)

// invisibleRune is one code point that draws no glyph and must not survive
// the sanitizer.
type invisibleRune struct {
	name string
	rune rune
}

// invisibleRunes are the code points the sanitizer drops: the private use
// characters, an unassigned code point, the Hangul fillers, the combining
// grapheme joiner, the Mongolian free variation selectors and vowel
// separator, and the variation selectors supplement.
func invisibleRunes(t *testing.T) []invisibleRune {
	t.Helper()
	return []invisibleRune{
		{"private use area", '\uE000'},
		{"private use area end", '\uF8FF'},
		{"supplementary private use area", '\U000F0000'},
		{"unassigned", unassignedRune(t)},
		{"hangul choseong filler", '\u115F'},
		{"hangul jungseong filler", '\u1160'},
		{"hangul filler", '\u3164'},
		{"halfwidth hangul filler", '\uFFA0'},
		{"combining grapheme joiner", '\u034F'},
		{"mongolian free variation selector one", '\u180B'},
		{"mongolian free variation selector four", '\u180D'},
		{"mongolian vowel separator", '\u180E'},
		{"variation selectors supplement", '\U000E0100'},
		{"variation selectors supplement end", '\U000E01EF'},
	}
}

// unassignedRune returns a code point that no Unicode category letter
// applies to, so the test does not depend on the Unicode version that the
// Go release ships.
func unassignedRune(t *testing.T) rune {
	t.Helper()
	for r := rune(0x0378); r <= 0xFFFF; r++ {
		if unicode.Is(unicode.Cn, r) {
			return r
		}
	}
	t.Fatal("no unassigned code point found")
	return 0
}

// TestCleanTextDropsInvisibleCharacters pins the promise that the invisible
// characters are dropped from a diagnostic detail, from a table cell, and
// from a CSV cell, so a name cannot carry a glyph it does not show.
func TestCleanTextDropsInvisibleCharacters(t *testing.T) {
	for _, test := range invisibleRunes(t) {
		t.Run(test.name, func(t *testing.T) {
			value := "a" + string(test.rune) + "b"
			const want = "ab"

			if got := SafeText(value); got != want {
				t.Errorf("SafeText(%q) = %q, want %q", value, got, want)
			}
			if got := sanitizeCell(value); got != want {
				t.Errorf("sanitizeCell(%q) = %q, want %q", value, got, want)
			}

			for _, format := range []string{"table", "csv"} {
				t.Run(format, func(t *testing.T) {
					var output bytes.Buffer
					if err := CT(&output, format, hostileCTDocument(value)); err != nil {
						t.Fatal(err)
					}
					rendered := output.String()
					if strings.ContainsRune(rendered, test.rune) {
						t.Errorf("%s output carries the invisible character %U", format, test.rune)
					}
					assertNoHostileRunes(t, rendered)
				})
			}
		})
	}
}

// TestCleanTextKeepsRealScriptCharacters pins the promise that the marks
// real scripts and emoji need are kept: the ordinary variation selectors,
// and the nonspacing marks that carry a vowel or a virama.
func TestCleanTextKeepsRealScriptCharacters(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
	}{
		// Promise: the variation selector that turns a heart into an emoji
		// survives, because the glyph depends on it.
		{"heart with variation selector", "\u2764\uFE0F"},
		// Promise: the combining acute accent survives, so an accented
		// letter is not stripped of its accent.
		{"e with combining acute", "e\u0301"},
		// Promise: the Thai vowel mark survives, so a Thai syllable keeps
		// its vowel.
		{"thai with combining vowel", "\u0E01\u0E32\u0E34"},
		// Promise: the Devanagari virama survives, so a conjunct is not
		// broken apart.
		{"devanagari with virama", "\u0915\u094D\u0937"},
		// Promise: ordinary CJK text survives untouched.
		{"cjk", "\u4F60\u597D\u4E16\u754C"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := SafeText(test.value); got != test.value {
				t.Errorf("SafeText(%q) = %q, want the value unchanged", test.value, got)
			}
			if got := sanitizeCell(test.value); got != test.value {
				t.Errorf("sanitizeCell(%q) = %q, want the value unchanged", test.value, got)
			}

			for _, format := range []string{"table", "csv"} {
				t.Run(format, func(t *testing.T) {
					var output bytes.Buffer
					if err := CT(&output, format, hostileCTDocument(test.value)); err != nil {
						t.Fatal(err)
					}
					rendered := output.String()
					if !strings.Contains(rendered, test.value) {
						t.Errorf("%s output is missing the value %q:\n%s", format, test.value, rendered)
					}
					assertNoHostileRunes(t, rendered)
				})
			}
		})
	}
}
