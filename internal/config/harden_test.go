package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/HarnageaGabriel/scadenza/internal/safefile"
)

// devicePath names a character device on this platform.
func devicePath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return "NUL"
	}
	return "/dev/null"
}

// paddedDocument returns a configuration document of exactly size bytes. The
// padding is a comment, so the document stays valid.
func paddedDocument(size int) string {
	prefix := "version: 1\n"
	padding := size - len(prefix) - len("#\n")
	if padding < 0 {
		panic("the size is too small for a configuration document")
	}
	return prefix + "#" + strings.Repeat("x", padding) + "\n"
}

func TestLoadReadsARegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scadenza.yaml")
	if err := os.WriteFile(path, []byte("version: 1\ndomains: [example.com]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.Version != 1 || len(config.Domains) != 1 {
		t.Fatalf("config = %+v", config)
	}
}

func TestLoadRejectsADirectory(t *testing.T) {
	_, err := Load(t.TempDir())
	if !errors.Is(err, safefile.ErrNotRegular) {
		t.Fatalf("err = %v, want ErrNotRegular", err)
	}
}

func TestLoadRejectsADevice(t *testing.T) {
	_, err := Load(devicePath(t))
	if !errors.Is(err, safefile.ErrNotRegular) {
		t.Fatalf("err = %v, want ErrNotRegular", err)
	}
}

func TestLoadRejectsANamedPipe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := safefile.CreatePipe(path); err != nil {
		t.Skipf("named pipes are not available: %v", err)
	}
	_, err := Load(path)
	if !errors.Is(err, safefile.ErrNotRegular) {
		t.Fatalf("err = %v, want ErrNotRegular", err)
	}
}

func TestLoadAcceptsAFileAtTheLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scadenza.yaml")
	if err := os.WriteFile(path, []byte(paddedDocument(MaxFileBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.Version != 1 {
		t.Fatalf("version = %d", config.Version)
	}
}

func TestLoadRejectsAFileOverTheLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scadenza.yaml")
	if err := os.WriteFile(path, []byte(paddedDocument(MaxFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if !errors.Is(err, safefile.ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("err = %v, want the path in the message", err)
	}
}

func TestParseRejectsASecondDocument(t *testing.T) {
	_, err := Parse([]byte("version: 1\n---\nversion: 1\n"))
	if !errors.Is(err, safefile.ErrMultipleDocuments) {
		t.Fatalf("err = %v, want ErrMultipleDocuments", err)
	}
}

func TestParseRejectsDeepNesting(t *testing.T) {
	var builder strings.Builder
	indent := ""
	for range 100 {
		builder.WriteString(indent + "level:\n")
		indent += "  "
	}
	builder.WriteString(indent + "value: 1\n")
	if _, err := Parse([]byte(builder.String())); err == nil {
		t.Fatal("expected an error for a deeply nested document")
	}
}
