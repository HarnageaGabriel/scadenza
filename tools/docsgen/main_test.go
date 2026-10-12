package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/HarnageaGabriel/scadenza/internal/diag"
)

func TestGenerateAndCheck(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, false); err != nil {
		t.Fatal(err)
	}
	if err := run(dir, true); err != nil {
		t.Fatalf("fresh output drifted: %v", err)
	}
	page := filepath.Join(dir, diag.List()[0].Code+".md")
	if err := os.WriteFile(page, []byte("drift"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(dir, true); err == nil {
		t.Fatal("expected drift error")
	}
}

func TestCommittedDiagnosticPages(t *testing.T) {
	if err := run(filepath.Join("..", "..", "docs", "diagnostics"), true); err != nil {
		t.Fatal(err)
	}
}
