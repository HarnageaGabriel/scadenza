// Command schemadiff reports the changes between two JSON Schema files that
// break the consumers of the older contract, as ADR 0007 requires.
package main

import (
	"cmp"
	"fmt"
	"io"
	"os"
	"slices"
)

const (
	breakLabel = "BREAK"
	noteLabel  = "note"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: schemadiff OLD NEW")
		os.Exit(2)
	}
	breaks, err := diffFiles(os.Args[1], os.Args[2], os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if breaks > 0 {
		os.Exit(1)
	}
}

// diffFiles compares two schema files and writes the findings to out. It
// returns the number of breaking changes.
func diffFiles(oldPath, newPath string, out io.Writer) (int, error) {
	old, err := loadDocument(oldPath)
	if err != nil {
		return 0, err
	}
	updated, err := loadDocument(newPath)
	if err != nil {
		return 0, err
	}
	findings := diff(old, updated)
	if err := writeFindings(out, findings); err != nil {
		return 0, err
	}
	return countBreaks(findings), nil
}

// writeFindings writes one finding per line, sorted by path.
func writeFindings(out io.Writer, findings []finding) error {
	slices.SortStableFunc(findings, func(left, right finding) int {
		if left.path != right.path {
			return cmp.Compare(left.path, right.path)
		}
		return cmp.Compare(left.reason, right.reason)
	})
	for _, item := range findings {
		label := breakLabel
		if item.note {
			label = noteLabel
		}
		if _, err := fmt.Fprintf(out, "%s %s: %s\n", label, location(item.path), item.reason); err != nil {
			return fmt.Errorf("write findings: %w", err)
		}
	}
	return nil
}

// countBreaks returns the number of findings that break the old contract.
func countBreaks(findings []finding) int {
	count := 0
	for _, item := range findings {
		if !item.note {
			count++
		}
	}
	return count
}

// location renders the JSON pointer of a finding.
func location(path string) string {
	if path == "" {
		return "/"
	}
	return path
}
