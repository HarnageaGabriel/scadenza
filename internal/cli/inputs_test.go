package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/HarnageaGabriel/scadenza/internal/kube"
	"github.com/HarnageaGabriel/scadenza/internal/owner"
	"github.com/HarnageaGabriel/scadenza/internal/safefile"
)

// ownerSignals returns the signals of one object that carries the given
// certificate name.
func ownerSignals(name string) owner.Signals {
	return owner.Signals{Object: "secret/ns/name", Names: []string{name}}
}

// devicePath names a character device on this platform.
func devicePath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return "NUL"
	}
	return "/dev/null"
}

// paddedHostsFile returns a hosts file of exactly size bytes that declares no
// host.
func paddedHostsFile(size int) string {
	var builder strings.Builder
	for builder.Len() < size {
		remaining := size - builder.Len()
		if remaining > 64 {
			builder.WriteString("# " + strings.Repeat("x", 61) + "\n")
			continue
		}
		builder.WriteString(strings.Repeat("#", remaining-1) + "\n")
	}
	return builder.String()
}

func TestReadHostsFileReadsARegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(path, []byte("# comment\nwww.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hosts, err := readHostsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0] != "www.example.com" {
		t.Fatalf("hosts = %v", hosts)
	}
}

func TestReadHostsFileRejectsADirectory(t *testing.T) {
	_, err := readHostsFile(t.TempDir())
	if !errors.Is(err, safefile.ErrNotRegular) {
		t.Fatalf("err = %v, want ErrNotRegular", err)
	}
}

func TestReadHostsFileRejectsADevice(t *testing.T) {
	_, err := readHostsFile(devicePath(t))
	if !errors.Is(err, safefile.ErrNotRegular) {
		t.Fatalf("err = %v, want ErrNotRegular", err)
	}
}

func TestReadHostsFileRejectsANamedPipe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := safefile.CreatePipe(path); err != nil {
		t.Skipf("named pipes are not available: %v", err)
	}
	_, err := readHostsFile(path)
	if !errors.Is(err, safefile.ErrNotRegular) {
		t.Fatalf("err = %v, want ErrNotRegular", err)
	}
}

func TestReadHostsFileAcceptsAFileAtTheLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(path, []byte(paddedHostsFile(maxHostsFileBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	hosts, err := readHostsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 0 {
		t.Fatalf("hosts = %v", hosts)
	}
}

func TestReadHostsFileRejectsAFileOverTheLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(path, []byte(paddedHostsFile(maxHostsFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readHostsFile(path)
	if !errors.Is(err, safefile.ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("err = %v, want the path in the message", err)
	}
}

func TestReadHostsFileAcceptsTheEntryLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.txt")
	content := strings.Repeat("www.example.com\n", MaxHostsEntries)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	hosts, err := readHostsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != MaxHostsEntries {
		t.Fatalf("hosts = %d entries", len(hosts))
	}
}

func TestReadHostsFileRejectsTooManyEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.txt")
	content := strings.Repeat("www.example.com\n", MaxHostsEntries+1)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readHostsFile(path)
	if err == nil {
		t.Fatal("expected an error for too many entries")
	}
	if !strings.Contains(err.Error(), "10000") {
		t.Errorf("err = %v, want the limit in the message", err)
	}
}

func TestLoadOwnershipReadsARegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owners.yaml")
	if err := os.WriteFile(path, []byte("domains:\n  example.com: team-web\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	parsed, err := loadOwnership(path, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	owners := parsed.Resolve(ownerSignals("example.com"))
	if len(owners) != 1 || owners[0].Value != "team-web" {
		t.Fatalf("owners = %+v", owners)
	}
}

func TestLoadOwnershipRejectsADirectory(t *testing.T) {
	var stderr bytes.Buffer
	_, err := loadOwnership(t.TempDir(), &stderr)
	if !errors.Is(err, safefile.ErrNotRegular) {
		t.Fatalf("err = %v, want ErrNotRegular", err)
	}
	if !strings.Contains(stderr.String(), kube.CodeOwnershipFileInvalid) {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestLoadOwnershipRejectsADevice(t *testing.T) {
	var stderr bytes.Buffer
	_, err := loadOwnership(devicePath(t), &stderr)
	if !errors.Is(err, safefile.ErrNotRegular) {
		t.Fatalf("err = %v, want ErrNotRegular", err)
	}
}

func TestLoadOwnershipRejectsANamedPipe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := safefile.CreatePipe(path); err != nil {
		t.Skipf("named pipes are not available: %v", err)
	}
	var stderr bytes.Buffer
	_, err := loadOwnership(path, &stderr)
	if !errors.Is(err, safefile.ErrNotRegular) {
		t.Fatalf("err = %v, want ErrNotRegular", err)
	}
}

func TestLoadOwnershipAcceptsAFileAtTheLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owners.yaml")
	document := "domains:\n  example.com: team-web\n"
	padding := maxOwnershipFileBytes - len(document) - len("#\n")
	if padding < 0 {
		t.Fatal("the limit is too small for the document")
	}
	if err := os.WriteFile(path, []byte(document+"#"+strings.Repeat("x", padding)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	parsed, err := loadOwnership(path, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	owners := parsed.Resolve(ownerSignals("example.com"))
	if len(owners) != 1 || owners[0].Value != "team-web" {
		t.Fatalf("owners = %+v", owners)
	}
}

func TestLoadOwnershipRejectsAFileOverTheLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owners.yaml")
	document := "domains:\n  example.com: team-web\n"
	padding := maxOwnershipFileBytes - len(document) - len("#\n")
	if err := os.WriteFile(path, []byte(document+"#"+strings.Repeat("x", padding+1)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	_, err := loadOwnership(path, &stderr)
	if !errors.Is(err, safefile.ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

func TestScanConfigErrorCarriesNoEscapeOrLineBreak(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scadenza.yaml")
	// The scalar holds a terminal escape and a line break: neither may
	// reach the terminal.
	document := "version: \"a\\u001bb\\nc\"\n"
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := execute(context.Background(), []string{"scan", "--config", path}, &stdout, &stderr, scanDependencies("x", fakeProber{}))
	if code != ExitUsageError {
		t.Fatalf("exit = %d; stderr=%s", code, stderr.String())
	}
	text := stderr.String()
	if strings.Contains(text, "\x1b") {
		t.Errorf("stderr carries an escape sequence: %q", text)
	}
	if strings.Contains(strings.TrimSuffix(text, "\n"), "\n") {
		t.Errorf("stderr carries a line break: %q", text)
	}
	if !strings.Contains(text, "SCD-0022") {
		t.Errorf("stderr does not name the configuration diagnostic: %q", text)
	}
}
