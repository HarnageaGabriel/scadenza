// Command docsgen generates the diagnostic reference from the embedded registry.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/HarnageaGabriel/scadenza/internal/diag"
)

func main() {
	out := flag.String("out", "docs/diagnostics", "output directory")
	check := flag.Bool("check", false, "fail if generated files differ")
	flag.Parse()
	if err := run(*out, *check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(out string, check bool) error {
	if err := diag.RegistryError(); err != nil {
		return err
	}
	pages := render(diag.List())
	if check {
		return verify(out, pages)
	}
	return write(out, pages)
}

func render(entries []diag.Diagnostic) map[string][]byte {
	pages := make(map[string][]byte, len(entries)+1)
	var index strings.Builder
	index.WriteString("# Diagnostic reference\n\nGenerated from `internal/diag/registry.yaml`. Do not edit by hand.\n\n")
	for _, entry := range entries {
		fmt.Fprintf(&index, "- [%s — %s](%s.md)\n", entry.Code, entry.Summary, entry.Code)
		pages[entry.Code+".md"] = []byte(fmt.Sprintf(
			"# %s: %s\n\n- Slug: `%s`\n- Severity: `%s`\n\n## Explanation\n\n%s\n\n## Remediation\n\n%s\n",
			entry.Code, entry.Summary, entry.Slug, entry.Severity, entry.Explanation, entry.Remediation,
		))
	}
	pages["README.md"] = []byte(index.String())
	return pages
}

func write(out string, pages map[string][]byte) error {
	if err := os.MkdirAll(out, 0o750); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	for name, content := range pages {
		if err := os.WriteFile(filepath.Join(out, name), content, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return removeStale(out, pages)
}

func removeStale(out string, pages map[string][]byte) error {
	existing, err := filepath.Glob(filepath.Join(out, "*.md"))
	if err != nil {
		return err
	}
	for _, path := range existing {
		if _, ok := pages[filepath.Base(path)]; !ok {
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("remove stale page %s: %w", path, err)
			}
		}
	}
	return nil
}

func verify(out string, pages map[string][]byte) error {
	var drift []string
	for name, want := range pages {
		got, err := os.ReadFile(filepath.Join(out, name)) //nolint:gosec // names are generated from validated codes
		if err != nil || !bytes.Equal(normalize(got), want) {
			drift = append(drift, name)
		}
	}
	existing, _ := filepath.Glob(filepath.Join(out, "*.md"))
	for _, path := range existing {
		if _, ok := pages[filepath.Base(path)]; !ok {
			drift = append(drift, filepath.Base(path)+" (stale)")
		}
	}
	if len(drift) > 0 {
		sort.Strings(drift)
		return fmt.Errorf("generated docs out of date (run `make docs`): %s", strings.Join(drift, ", "))
	}
	return nil
}

func normalize(data []byte) []byte { return bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")) }
