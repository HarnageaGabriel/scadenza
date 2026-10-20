package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// devicePath names a character device on this platform.
func devicePath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return "NUL"
	}
	return "/dev/null"
}

func TestReadReadsARegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(path, []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := Read(path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello\n" {
		t.Fatalf("data = %q", data)
	}
}

func TestReadRejectsAMissingFile(t *testing.T) {
	_, err := Read(filepath.Join(t.TempDir(), "missing.txt"), 1024)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want a not-exist error", err)
	}
}

func TestReadRejectsADirectory(t *testing.T) {
	directory := t.TempDir()
	_, err := Read(directory, 1024)
	if !errors.Is(err, ErrNotRegular) {
		t.Fatalf("err = %v, want ErrNotRegular", err)
	}
	if !strings.Contains(err.Error(), directory) {
		t.Fatalf("err = %v, want the path in the message", err)
	}
}

func TestReadRejectsADevice(t *testing.T) {
	_, err := Read(devicePath(t), 1024)
	if !errors.Is(err, ErrNotRegular) {
		t.Fatalf("err = %v, want ErrNotRegular", err)
	}
}

func TestReadRejectsANamedPipe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := CreatePipe(path); err != nil {
		t.Skipf("named pipes are not available: %v", err)
	}
	_, err := Read(path, 1024)
	if !errors.Is(err, ErrNotRegular) {
		t.Fatalf("err = %v, want ErrNotRegular", err)
	}
}

func TestReadAcceptsAFileAtTheLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.txt")
	content := strings.Repeat("a", 4096)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := Read(path, int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != len(content) {
		t.Fatalf("len(data) = %d, want %d", len(data), len(content))
	}
}

func TestReadRejectsAFileOverTheLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.txt")
	content := strings.Repeat("a", 4096)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Read(path, int64(len(content))-1)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("err = %v, want the path in the message", err)
	}
	if !strings.Contains(err.Error(), "4095") {
		t.Errorf("err = %v, want the limit in the message", err)
	}
}

func TestReadFollowsASymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.txt")
	if err := os.WriteFile(target, []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}
	data, err := Read(link, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello\n" {
		t.Fatalf("data = %q", data)
	}
}

func TestReadRejectsASymlinkToADirectory(t *testing.T) {
	directory := t.TempDir()
	link := filepath.Join(directory, "link")
	if err := os.Symlink(directory, link); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}
	_, err := Read(link, 1024)
	if !errors.Is(err, ErrNotRegular) {
		t.Fatalf("err = %v, want ErrNotRegular", err)
	}
}
