// Package cli owns the scadenza command-line interface.
package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/HarnageaGabriel/scadenza/internal/version"
	"github.com/spf13/cobra"
)

const (
	// ExitOK indicates successful completion.
	ExitOK = 0
	// ExitInternalError indicates an unexpected internal failure.
	ExitInternalError = 1
	// ExitUsageError indicates invalid command-line usage or input.
	ExitUsageError = 2
	// ExitFindingsPresent is reserved for commands that report findings.
	ExitFindingsPresent = 3
	// ExitSourceUnavailable indicates a required source could not be used.
	ExitSourceUnavailable = 4
	// ExitIncompleteScan indicates the scan did not check everything it was
	// asked to check (--strict or --min-coverage).
	ExitIncompleteScan = 5
)

// Execute runs the CLI and converts command errors to documented exit codes.
func Execute(args []string, stdout, stderr io.Writer) int {
	return execute(args, stdout, stderr, productionCTDependencies())
}

// execute runs the command line and converts its errors to documented exit
// codes. Cobra adds the commands it provides itself (help, completion, and the
// hidden completion request) while it runs, so the command line is only
// checked against the complete command tree after the run.
func execute(args []string, stdout, stderr io.Writer, dependencies ctDependencies) int {
	root := newRootCommand(stdout, stderr, dependencies)
	root.SetArgs(args)
	err := root.Execute()
	if err == nil {
		return ExitOK
	}
	if _, _, findErr := root.Find(args); findErr != nil {
		// The first word of the command line names no command, so the run
		// failed on the command line itself.
		printUsageError(root, findErr)
		return ExitUsageError
	}
	return exitCode(err)
}

// printUsageError writes the usage error of an unknown command the way cobra
// writes it, so the message is the one the command line produced.
func printUsageError(root *cobra.Command, err error) {
	root.PrintErrln(root.ErrPrefix(), err.Error())
	root.PrintErrf("Run '%v --help' for usage.\n", root.CommandPath())
}

func newRootCommand(stdout, stderr io.Writer, dependencies ctDependencies) *cobra.Command {
	root := &cobra.Command{
		Use:           "scadenza",
		Short:         "Inspect public TLS certificate readiness",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return &commandError{code: ExitUsageError, err: err} })
	versionCommand := newVersionCommand(stdout)
	ctCommand := newCTCommand(stdout, stderr, dependencies)
	scanCommand := newScanCommand(stdout, stderr, dependencies)
	root.AddCommand(versionCommand)
	root.AddCommand(ctCommand)
	root.AddCommand(scanCommand)
	// Cobra adds the help and completion commands it provides itself while it
	// runs. They are added here so that their argument errors keep the
	// documented usage exit code.
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	for _, command := range root.Commands() {
		if command == versionCommand || command == ctCommand || command == scanCommand {
			continue
		}
		usageArgsFor(command)
	}
	return root
}

// usageArgsFor gives the commands cobra provides itself the same usage exit
// code as the program's own commands.
func usageArgsFor(command *cobra.Command) {
	if command.Args != nil {
		command.Args = usageArgs(command.Args)
	}
	for _, child := range command.Commands() {
		usageArgsFor(child)
	}
}

func newVersionCommand(stdout io.Writer) *cobra.Command {
	var asJSON bool
	command := &cobra.Command{
		Use:   "version",
		Short: "Print build version information",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(_ *cobra.Command, _ []string) error {
			info := version.Current()
			if asJSON {
				encoder := json.NewEncoder(stdout)
				encoder.SetEscapeHTML(false)
				return encoder.Encode(info)
			}
			_, err := fmt.Fprintf(stdout, "scadenza %s\ncommit: %s\ndate: %s\n", info.Version, info.Commit, info.Date)
			return err
		},
	}
	command.Flags().BoolVar(&asJSON, "json", false, "print version information as JSON")
	return command
}
