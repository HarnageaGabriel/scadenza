package config

import (
	"errors"
	"testing"
)

// TestRenewalKeysUseSharedNormalizer pins M4b review finding 7: a renewal key
// is normalized with the shared domain normalizer, so a trailing dot or a
// wildcard prefix still matches the certificate name instead of silently
// dropping the declaration.
func TestRenewalKeysUseSharedNormalizer(t *testing.T) {
	cases := map[string]string{
		"example.com.":       "example.com",
		"*.Example.COM":      "example.com",
		"*.Example.COM.":     "example.com",
		"  Example.com  ":    "example.com",
		"*.WWW.example.com.": "www.example.com",
	}
	for key, want := range cases {
		parsed, err := Parse([]byte("version: 1\nrenewal:\n  \"" + key + "\": manual\n"))
		if err != nil {
			t.Fatalf("Parse(%q): %v", key, err)
		}
		if len(parsed.Renewal) != 1 || parsed.Renewal[want] != RenewalManual {
			t.Fatalf("renewal for %q = %v, want {%q: manual}", key, parsed.Renewal, want)
		}
	}
}

// TestRenewalKeysRejectMalformed pins the other half of finding 7: a key that is
// not a domain is an error, not a silently ignored declaration.
func TestRenewalKeysRejectMalformed(t *testing.T) {
	for _, key := range []string{"", "exa..mple.com", "not a domain", "*", "example.com/path", "1.2.3.4", "example.com:443"} {
		data := "version: 1\nrenewal:\n  \"" + key + "\": manual\n"
		_, err := Parse([]byte(data))
		if err == nil {
			t.Errorf("Parse(%q) accepted a malformed renewal key", key)
			continue
		}
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("Parse(%q) err = %v, want ErrInvalid", key, err)
		}
	}
}

// TestRenewalConfigInvalidFailOnKind pins M4b review finding 2: the new kind is
// selectable, and it is not on by default.
func TestRenewalConfigInvalidFailOnKind(t *testing.T) {
	kinds, err := ParseFailOn("renewal-config-invalid")
	if err != nil || len(kinds) != 1 || kinds[0] != "renewal-config-invalid" {
		t.Fatalf("kinds = %v err = %v", kinds, err)
	}
	for _, kind := range DefaultFailOn() {
		if kind == "renewal-config-invalid" {
			t.Fatal("renewal-config-invalid must not be on by default")
		}
	}
}
