package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestDiffRules(t *testing.T) {
	cases := []struct {
		name string
		old  string
		new  string
		want []string
	}{
		{
			name: "property removed",
			old:  `{"type":"object","properties":{"name":{"type":"string"},"count":{"type":"integer"}}}`,
			new:  `{"type":"object","properties":{"name":{"type":"string"}}}`,
			want: []string{`BREAK /properties/count: property removed`},
		},
		{
			name: "type changed",
			old:  `{"properties":{"name":{"type":"string"}}}`,
			new:  `{"properties":{"name":{"type":"integer"}}}`,
			want: []string{`BREAK /properties/name: type changed: "string" is no longer accepted (was ["string"], now ["integer"])`},
		},
		{
			name: "type list lost a member",
			old:  `{"properties":{"revoked":{"type":["boolean","null"]}}}`,
			new:  `{"properties":{"revoked":{"type":["boolean"]}}}`,
			want: []string{`BREAK /properties/revoked: type changed: "null" is no longer accepted (was ["boolean", "null"], now ["boolean"])`},
		},
		{
			name: "type list gained a member",
			old:  `{"properties":{"revoked":{"type":"boolean"}}}`,
			new:  `{"properties":{"revoked":{"type":["boolean","null"]}}}`,
			want: []string{},
		},
		{
			name: "integer widened to number",
			old:  `{"properties":{"n":{"type":"integer"}}}`,
			new:  `{"properties":{"n":{"type":"number"}}}`,
			want: []string{},
		},
		{
			name: "optional became required is a note",
			old:  `{"properties":{"name":{"type":"string"}}}`,
			new:  `{"properties":{"name":{"type":"string"}},"required":["name"]}`,
			want: []string{`note /properties/name: property changed from optional to required`},
		},
		{
			name: "new required property is a note",
			old:  `{"properties":{"name":{"type":"string"}},"required":["name"]}`,
			new:  `{"properties":{"name":{"type":"string"},"extra":{"type":"string"}},"required":["name","extra"]}`,
			want: []string{`note /properties/extra: new required property`},
		},
		{
			name: "enum value removed",
			old:  `{"properties":{"kind":{"enum":["a","b"]}}}`,
			new:  `{"properties":{"kind":{"enum":["a"]}}}`,
			want: []string{`BREAK /properties/kind: enum value "b" removed`},
		},
		{
			name: "enum value added is a note",
			old:  `{"properties":{"kind":{"enum":["a"]}}}`,
			new:  `{"properties":{"kind":{"enum":["a","b"]}}}`,
			want: []string{`note /properties/kind: enum value "b" added`},
		},
		{
			name: "pattern became stricter",
			old:  `{"properties":{"code":{"type":"string","pattern":"^a.*$"}}}`,
			new:  `{"properties":{"code":{"type":"string","pattern":"^ab.*$"}}}`,
			want: []string{`BREAK /properties/code: pattern changed from "^a.*$" to "^ab.*$" and the new one is not provably looser`},
		},
		{
			name: "pattern got an alternative",
			old:  `{"properties":{"code":{"type":"string","pattern":"^a$"}}}`,
			new:  `{"properties":{"code":{"type":"string","pattern":"^a$|^b$"}}}`,
			want: []string{},
		},
		{
			name: "pattern removed",
			old:  `{"properties":{"code":{"type":"string","pattern":"^a$"}}}`,
			new:  `{"properties":{"code":{"type":"string"}}}`,
			want: []string{},
		},
		{
			name: "minimum increased",
			old:  `{"properties":{"n":{"type":"integer","minimum":0}}}`,
			new:  `{"properties":{"n":{"type":"integer","minimum":1}}}`,
			want: []string{`BREAK /properties/n: minimum increased from 0 to 1`},
		},
		{
			name: "maximum decreased",
			old:  `{"properties":{"n":{"type":"integer","maximum":65535}}}`,
			new:  `{"properties":{"n":{"type":"integer","maximum":1024}}}`,
			want: []string{`BREAK /properties/n: maximum decreased from 65535 to 1024`},
		},
		{
			name: "minLength increased",
			old:  `{"properties":{"s":{"type":"string","minLength":1}}}`,
			new:  `{"properties":{"s":{"type":"string","minLength":2}}}`,
			want: []string{`BREAK /properties/s: minLength increased from 1 to 2`},
		},
		{
			name: "maxLength decreased",
			old:  `{"properties":{"s":{"type":"string","maxLength":10}}}`,
			new:  `{"properties":{"s":{"type":"string","maxLength":5}}}`,
			want: []string{`BREAK /properties/s: maxLength decreased from 10 to 5`},
		},
		{
			name: "constraint got looser",
			old:  `{"properties":{"n":{"type":"integer","minimum":1,"maximum":10}}}`,
			new:  `{"properties":{"n":{"type":"integer","minimum":0,"maximum":20}}}`,
			want: []string{},
		},
		{
			name: "additionalProperties forbidden",
			old:  `{"type":"object","properties":{"name":{"type":"string"}}}`,
			new:  `{"type":"object","properties":{"name":{"type":"string"}},"additionalProperties":false}`,
			want: []string{`BREAK /: additionalProperties changed from allowed to false`},
		},
		{
			name: "additionalProperties allowed again",
			old:  `{"type":"object","properties":{"name":{"type":"string"}},"additionalProperties":false}`,
			new:  `{"type":"object","properties":{"name":{"type":"string"}}}`,
			want: []string{},
		},
		{
			name: "additionalProperties became a schema",
			old:  `{"type":"object","properties":{"name":{"type":"string"}}}`,
			new:  `{"type":"object","properties":{"name":{"type":"string"}},"additionalProperties":{"type":"string"}}`,
			want: []string{`BREAK /: additionalProperties became constrained by a schema`},
		},
		{
			name: "additionalProperties schema turned false",
			old:  `{"type":"object","properties":{"name":{"type":"string"}},"additionalProperties":{"type":"string"}}`,
			new:  `{"type":"object","properties":{"name":{"type":"string"}},"additionalProperties":false}`,
			want: []string{`BREAK /: additionalProperties changed from a schema to false`},
		},
		{
			name: "const changed",
			old:  `{"properties":{"schema_version":{"const":"scadenza.ct/v1"}}}`,
			new:  `{"properties":{"schema_version":{"const":"scadenza.ct/v2"}}}`,
			want: []string{`BREAK /properties/schema_version: const changed from "scadenza.ct/v1" to "scadenza.ct/v2"`},
		},
		{
			name: "array item type changed",
			old:  `{"properties":{"sources":{"type":"array","items":{"type":"string"}}}}`,
			new:  `{"properties":{"sources":{"type":"array","items":{"type":"integer"}}}}`,
			want: []string{`BREAK /properties/sources/items: type changed: "string" is no longer accepted (was ["string"], now ["integer"])`},
		},
		{
			name: "definition removed while referenced",
			old: `{"$defs":{"note":{"type":"object","properties":{"text":{"type":"string"}}}},"type":"object",` +
				`"properties":{"note":{"$ref":"#/$defs/note"}}}`,
			new:  `{"type":"object","properties":{"note":{"$ref":"#/$defs/note"}}}`,
			want: []string{`BREAK /$defs/note: definition removed while still referenced by /properties/note`},
		},
		{
			name: "definition removed and no longer referenced",
			old: `{"$defs":{"note":{"type":"object","properties":{"text":{"type":"string"}}}},"type":"object",` +
				`"properties":{"name":{"type":"string"}}}`,
			new:  `{"type":"object","properties":{"name":{"type":"string"}}}`,
			want: []string{},
		},
		{
			name: "referenced definition changed",
			old: `{"$defs":{"note":{"type":"object","properties":{"text":{"type":"string"}}}},"type":"object",` +
				`"properties":{"note":{"$ref":"#/$defs/note"}}}`,
			new: `{"$defs":{"note":{"type":"object","properties":{"text":{"type":"integer"}}}},"type":"object",` +
				`"properties":{"note":{"$ref":"#/$defs/note"}}}`,
			want: []string{`BREAK /properties/note/properties/text: type changed: "string" is no longer accepted (was ["string"], now ["integer"])`},
		},
		{
			name: "new definition",
			old:  `{"type":"object","properties":{"name":{"type":"string"}}}`,
			new: `{"$defs":{"note":{"type":"object"}},"type":"object",` +
				`"properties":{"name":{"type":"string"}}}`,
			want: []string{},
		},
		{
			name: "new optional property",
			old:  `{"type":"object","properties":{"name":{"type":"string"}}}`,
			new:  `{"type":"object","properties":{"name":{"type":"string"},"extra":{"type":"string"}}}`,
			want: []string{},
		},
		{
			name: "required became optional is a note",
			old:  `{"properties":{"name":{"type":"string"}},"required":["name"]}`,
			new:  `{"properties":{"name":{"type":"string"}}}`,
			want: []string{`note /properties/name: property changed from required to optional; consumers relying on presence may be affected`},
		},
		{
			name: "required property removed",
			old:  `{"properties":{"name":{"type":"string"}},"required":["name"]}`,
			new:  `{"properties":{}}`,
			want: []string{`BREAK /properties/name: property removed`},
		},
		{
			name: "identical schemas",
			old:  `{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`,
			new:  `{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`,
			want: []string{},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			output, breaks := runDiff(t, test.old, test.new)
			got := splitLines(output)
			if diff := cmp.Diff(got, test.want); diff != "" {
				t.Errorf("output mismatch (-got +want):\n%s", diff)
			}
			if want := countBreakLines(test.want); breaks != want {
				t.Errorf("breaks = %d, want %d", breaks, want)
			}
		})
	}
}

func TestPublishedSchemasCompareWithThemselves(t *testing.T) {
	for _, name := range []string{"ct-v1.schema.json", "scan-v1.schema.json"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("..", "..", "docs", "schema", name)
			var out bytes.Buffer
			breaks, err := diffFiles(path, path, &out)
			if err != nil {
				t.Fatal(err)
			}
			if breaks != 0 || out.Len() != 0 {
				t.Fatalf("breaks = %d, output:\n%s", breaks, out.String())
			}
		})
	}
}

func TestCommandExitCodes(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain on PATH")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "schemadiff")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command(goTool, "build", "-o", binary, ".")
	// The child build reuses the toolchain that compiled the test, so that a
	// toolchain switch cannot race with the test run.
	build.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOROOT="+goEnv(t, goTool, "GOROOT"))
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, output)
	}
	oldPath := filepath.Join(dir, "old.json")
	newPath := filepath.Join(dir, "new.json")
	writeFile(t, oldPath, `{"properties":{"name":{"type":"string"}}}`)
	writeFile(t, newPath, `{"properties":{"name":{"type":"integer"}}}`)

	cases := []struct {
		name     string
		args     []string
		wantCode int
	}{
		{"no arguments", nil, 2},
		{"one argument", []string{oldPath}, 2},
		{"missing file", []string{filepath.Join(dir, "absent.json"), newPath}, 2},
		{"breaking change", []string{oldPath, newPath}, 1},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command(binary, test.args...)
			output, err := command.CombinedOutput()
			code := 0
			var exit *exec.ExitError
			switch {
			case errors.As(err, &exit):
				code = exit.ExitCode()
			case err != nil:
				t.Fatalf("run failed: %v", err)
			}
			if code != test.wantCode {
				t.Fatalf("exit code = %d, want %d, output:\n%s", code, test.wantCode, output)
			}
		})
	}

	t.Run("compatible schemas exit zero", func(t *testing.T) {
		same := filepath.Join(dir, "same.json")
		writeFile(t, same, `{"properties":{"name":{"type":"string"}}}`)
		output, err := exec.Command(binary, same, same).CombinedOutput()
		if err != nil {
			t.Fatalf("run failed: %v\n%s", err, output)
		}
		if len(output) != 0 {
			t.Fatalf("expected no output, got:\n%s", output)
		}
	})

	t.Run("a note does not fail", func(t *testing.T) {
		noteOld := filepath.Join(dir, "note-old.json")
		noteNew := filepath.Join(dir, "note-new.json")
		writeFile(t, noteOld, `{"properties":{"kind":{"enum":["a"]}}}`)
		writeFile(t, noteNew, `{"properties":{"kind":{"enum":["a","b"]}}}`)
		output, err := exec.Command(binary, noteOld, noteNew).CombinedOutput()
		if err != nil {
			t.Fatalf("run failed: %v\n%s", err, output)
		}
		if !strings.Contains(string(output), `note /properties/kind: enum value "b" added`) {
			t.Fatalf("missing note, got:\n%s", output)
		}
	})

	t.Run("a new required property does not fail", func(t *testing.T) {
		requiredOld := filepath.Join(dir, "required-old.json")
		requiredNew := filepath.Join(dir, "required-new.json")
		writeFile(t, requiredOld, `{"properties":{"name":{"type":"string"}},"required":["name"]}`)
		writeFile(t, requiredNew, `{"properties":{"name":{"type":"string"},"extra":{"type":"string"}},"required":["name","extra"]}`)
		output, err := exec.Command(binary, requiredOld, requiredNew).CombinedOutput()
		if err != nil {
			t.Fatalf("run failed: %v\n%s", err, output)
		}
		if !strings.Contains(string(output), `note /properties/extra: new required property`) {
			t.Fatalf("missing note, got:\n%s", output)
		}
	})

	t.Run("a required property that became optional does not fail", func(t *testing.T) {
		optionalOld := filepath.Join(dir, "optional-old.json")
		optionalNew := filepath.Join(dir, "optional-new.json")
		writeFile(t, optionalOld, `{"properties":{"name":{"type":"string"}},"required":["name"]}`)
		writeFile(t, optionalNew, `{"properties":{"name":{"type":"string"}}}`)
		output, err := exec.Command(binary, optionalOld, optionalNew).CombinedOutput()
		if err != nil {
			t.Fatalf("run failed: %v\n%s", err, output)
		}
		if !strings.Contains(string(output), "consumers relying on presence") {
			t.Fatalf("missing note, got:\n%s", output)
		}
	})
}

// runDiff compares two schema documents given as JSON text.
func runDiff(t *testing.T, oldSchema, newSchema string) (string, int) {
	t.Helper()
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.json")
	newPath := filepath.Join(dir, "new.json")
	writeFile(t, oldPath, oldSchema)
	writeFile(t, newPath, newSchema)
	var out bytes.Buffer
	breaks, err := diffFiles(oldPath, newPath, &out)
	if err != nil {
		t.Fatal(err)
	}
	return out.String(), breaks
}

// writeFile writes a schema file for a test.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// goEnv returns a value of the go environment.
func goEnv(t *testing.T, goTool, name string) string {
	t.Helper()
	output, err := exec.Command(goTool, "env", name).Output()
	if err != nil {
		t.Fatalf("go env %s: %v", name, err)
	}
	return strings.TrimSpace(string(output))
}

// splitLines splits the output of the tool into its lines.
func splitLines(output string) []string {
	trimmed := strings.TrimSuffix(output, "\n")
	if trimmed == "" {
		return []string{}
	}
	return strings.Split(trimmed, "\n")
}

// countBreakLines counts the breaking lines of an expected output.
func countBreakLines(lines []string) int {
	count := 0
	for _, line := range lines {
		if strings.HasPrefix(line, breakLabel+" ") {
			count++
		}
	}
	return count
}
