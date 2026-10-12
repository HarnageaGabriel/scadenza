package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/HarnageaGabriel/scadenza/internal/version"
	"github.com/google/go-cmp/cmp"
)

func TestExecute(t *testing.T) {
	tests := []struct {
		name string
		args []string
		code int
	}{
		{name: "help", args: []string{"--help"}, code: ExitOK},
		{name: "version", args: []string{"version"}, code: ExitOK},
		{name: "unknown", args: []string{"unknown"}, code: ExitUsageError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := Execute(test.args, &stdout, &stderr); got != test.code {
				t.Fatalf("Execute() = %d, want %d", got, test.code)
			}
		})
	}
}

func TestVersionOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"version"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("Execute() = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(stdout.String(), "scadenza "+version.Version) {
		t.Fatalf("output %q does not contain version", stdout.String())
	}
}

func TestVersionJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"version", "--json"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("Execute() = %d, want %d", code, ExitOK)
	}
	var got version.Info
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if diff := cmp.Diff(version.Current(), got); diff != "" {
		t.Fatalf("JSON mismatch (-want +got):\n%s", diff)
	}
}
