package cli

import (
	"bytes"
	"strings"
	"testing"
)

// TestBuiltInCommandsSucceed covers the commands cobra provides itself. The
// CLI used to reject them as unknown commands, because it checked the command
// line before cobra had registered them.
func TestBuiltInCommandsSucceed(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "help", args: []string{"help"}},
		{name: "help scan", args: []string{"help", "scan"}},
		{name: "help ct", args: []string{"help", "ct"}},
		{name: "help version", args: []string{"help", "version"}},
		{name: "completion", args: []string{"completion"}},
		{name: "completion bash", args: []string{"completion", "bash"}},
		{name: "completion zsh", args: []string{"completion", "zsh"}},
		{name: "completion fish", args: []string{"completion", "fish"}},
		{name: "completion powershell", args: []string{"completion", "powershell"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Execute(test.args, &stdout, &stderr); code != ExitOK {
				t.Fatalf("Execute(%v) = %d, want %d; stderr=%s", test.args, code, ExitOK, stderr.String())
			}
			if stdout.Len() == 0 {
				t.Fatalf("Execute(%v) printed nothing on stdout", test.args)
			}
		})
	}
}

// TestCompletionScriptsNameTheProgram checks that every completion script
// names the program, so the script is the one for scadenza.
func TestCompletionScriptsNameTheProgram(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Execute([]string{"completion", shell}, &stdout, &stderr); code != ExitOK {
				t.Fatalf("Execute() = %d, want %d; stderr=%s", code, ExitOK, stderr.String())
			}
			if !strings.Contains(stdout.String(), "scadenza") {
				t.Fatalf("the %s completion script does not name the program", shell)
			}
		})
	}
}

// TestHelpFlagPrintsUsage checks the help flag on the root command and on
// every subcommand.
func TestHelpFlagPrintsUsage(t *testing.T) {
	tests := [][]string{
		{"--help"},
		{"version", "--help"},
		{"ct", "--help"},
		{"scan", "--help"},
		{"completion", "--help"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Execute(args, &stdout, &stderr); code != ExitOK {
				t.Fatalf("Execute(%v) = %d, want %d; stderr=%s", args, code, ExitOK, stderr.String())
			}
			if stdout.Len() == 0 {
				t.Fatalf("Execute(%v) printed nothing on stdout", args)
			}
		})
	}
}

// TestUnknownCommandIsUsageError checks that a first word that names no
// command still fails as a usage error and prints the usage error.
func TestUnknownCommandIsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"unknown"}, &stdout, &stderr); code != ExitUsageError {
		t.Fatalf("Execute() = %d, want %d", code, ExitUsageError)
	}
	if !strings.Contains(stderr.String(), `unknown command "unknown"`) {
		t.Fatalf("the usage error was not printed: %q", stderr.String())
	}
}
