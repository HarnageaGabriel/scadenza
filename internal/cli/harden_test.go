package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/HarnageaGabriel/scadenza/internal/diag"
	"github.com/HarnageaGabriel/scadenza/internal/render"
)

// hostileDetail is one untrusted value that a diagnostic detail can carry.
type hostileDetail struct {
	name   string
	detail string
}

// hostileDetails are the values a hostile Certificate Transparency log, a
// hostile cluster, or a hostile Key Vault can put into a name, a label, a
// tag, or an owner.
var hostileDetails = []hostileDetail{
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

// assertNoHostileRunes fails when a line carries a control character, a
// format character, or a line or paragraph separator.
func assertNoHostileRunes(t *testing.T, line string) {
	t.Helper()
	for _, r := range line {
		switch {
		case unicode.IsControl(r):
			t.Errorf("line carries the control character %U", r)
		case unicode.Is(unicode.Cf, r):
			t.Errorf("line carries the format character %U", r)
		case r == '\u2028' || r == '\u2029':
			t.Errorf("line carries the separator %U", r)
		}
	}
}

func TestEmitDiagnosticNeutralizesHostileDetails(t *testing.T) {
	item, ok := diag.Lookup("SCD-0008")
	if !ok {
		t.Fatal("missing SCD-0008")
	}
	prefix := "SCD-0008 [" + string(item.Severity) + "] " + item.Summary + ": "
	for _, hostile := range hostileDetails {
		t.Run(hostile.name, func(t *testing.T) {
			var stderr bytes.Buffer
			emitDiagnostic(&stderr, "SCD-0008", hostile.detail)
			line := stderr.String()
			if !strings.HasSuffix(line, "\n") {
				t.Fatalf("diagnostic line is not terminated: %q", line)
			}
			line = strings.TrimSuffix(line, "\n")
			if strings.ContainsAny(line, "\n\r") {
				t.Fatalf("diagnostic line carries a line break: %q", line)
			}
			if !strings.HasPrefix(line, prefix) {
				t.Errorf("diagnostic line does not start with %q: %q", prefix, line)
			}
			assertNoHostileRunes(t, line)
			detail := strings.TrimPrefix(line, prefix)
			if count := utf8.RuneCountInString(detail); count > render.MaxDetailRunes {
				t.Errorf("detail has %d runes, want at most %d", count, render.MaxDetailRunes)
			}
			if utf8.RuneCountInString(hostile.detail) > render.MaxDetailRunes && !strings.HasSuffix(detail, "…") {
				t.Errorf("detail %q does not end with an ellipsis", detail)
			}
		})
	}
}

func TestEmitDiagnosticWithoutDetailKeepsOneLine(t *testing.T) {
	item, ok := diag.Lookup("SCD-0005")
	if !ok {
		t.Fatal("missing SCD-0005")
	}
	var stderr bytes.Buffer
	emitDiagnostic(&stderr, "SCD-0005", "   ")
	line := stderr.String()
	if !strings.HasPrefix(line, "SCD-0005 ["+string(item.Severity)+"] "+item.Summary) {
		t.Fatalf("diagnostic line = %q", line)
	}
	if strings.Count(line, "\n") != 1 {
		t.Fatalf("diagnostic line is not one line: %q", line)
	}
}

func TestScanDiagnosticsNeutralizeHostileNames(t *testing.T) {
	for _, hostile := range hostileDetails {
		t.Run(hostile.name, func(t *testing.T) {
			name := "*.\u202EPASS." + hostile.detail + ".example.com"
			server := hostileCTServer(t, name)
			var stdout, stderr bytes.Buffer
			execute(context.Background(), []string{"scan", "--domain", "example.com", "--source", "certspotter", "--format", "json"}, &stdout, &stderr, scanDependencies(server.URL, fakeProber{}))
			lines := strings.Split(strings.TrimSuffix(stderr.String(), "\n"), "\n")
			if len(lines) == 0 || lines[0] == "" {
				t.Fatalf("no diagnostic on stderr: %q", stderr.String())
			}
			// A name that fails the host name validation is reported as not
			// checked instead of as a wildcard. Either way the name is
			// reported, and no forged line reaches stderr.
			if !strings.Contains(stderr.String(), "SCD-0008") &&
				!strings.Contains(stdout.String(), reasonInvalidName) {
				t.Fatalf("the hostile name was not reported: stderr=%q stdout=%q", stderr.String(), stdout.String())
			}
			for _, line := range lines {
				if !strings.HasPrefix(line, "SCD-") {
					t.Errorf("diagnostic line does not start with a diagnostic code: %q", line)
				}
				assertNoHostileRunes(t, line)
			}
			var document struct {
				Certificates []struct {
					Names []string `json:"names"`
				} `json:"certificates"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
				t.Fatal(err)
			}
			if len(document.Certificates) != 1 || len(document.Certificates[0].Names) != 1 {
				t.Fatalf("json names = %v", document.Certificates)
			}
			// The source lowercases the name, but the JSON keeps it complete.
			want := strings.ToLower(strings.TrimSpace(name))
			if document.Certificates[0].Names[0] != want {
				t.Errorf("json name = %q, want the full value %q", document.Certificates[0].Names[0], want)
			}
		})
	}
}

// hostileCTServer serves one Certificate Transparency record with the given
// subject name.
func hostileCTServer(t *testing.T, name string) *httptest.Server {
	t.Helper()
	body, err := json.Marshal([]map[string]any{{
		"id":          "1",
		"cert_sha256": strings.Repeat("a", 64),
		"dns_names":   []string{name},
		"issuer":      map[string]string{"name": "CN=Example Root"},
		"not_before":  "2026-01-01T00:00:00Z",
		"not_after":   "2026-04-01T00:00:00Z",
		"revoked":     false,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return certSpotterServer(t, string(body))
}
