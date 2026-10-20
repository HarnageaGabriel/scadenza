// Package cli owns the scadenza command-line interface.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	// ExitInterrupted indicates the run was stopped by an interrupt signal.
	// It is the code a shell expects from a process that was interrupted.
	ExitInterrupted = 130
)

// interruptedMessage is the one line a stopped run writes to stderr. It is
// static text, so it never carries a value from the interrupted run.
const interruptedMessage = "interrupted"

// ErrInterrupted is the cancellation cause of a run that was stopped by an
// interrupt signal. A context cancelled with this cause ends the run with
// ExitInterrupted and without a report; a context cancelled for any other
// reason keeps the ordinary exit codes.
var ErrInterrupted = errors.New(interruptedMessage)

// Execute runs the CLI and converts command errors to documented exit codes.
func Execute(args []string, stdout, stderr io.Writer) int {
	return ExecuteContext(context.Background(), args, stdout, stderr)
}

// ExecuteContext runs the CLI under the given context and converts command
// errors to documented exit codes. Cancelling the context with ErrInterrupted
// stops the run: no report is written, one line is written to stderr, and the
// run exits with ExitInterrupted.
func ExecuteContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return execute(ctx, args, stdout, stderr, productionCTDependencies())
}

// execute runs the command line under the given context and converts its
// errors to documented exit codes. Cobra adds the commands it provides itself
// (help, completion, and the hidden completion request) while it runs, so the
// command line is only checked against the complete command tree after the
// run.
func execute(ctx context.Context, args []string, stdout, stderr io.Writer, dependencies ctDependencies) int {
	root := newRootCommand(stdout, stderr, dependencies)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if interrupted(ctx) {
		// The run was stopped by a signal. It reports nothing: a partial
		// document would look like a result.
		_, _ = fmt.Fprintln(stderr, interruptedMessage)
		return ExitInterrupted
	}
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

// interrupted reports whether the run was stopped by an interrupt signal. A
// context cancelled for any other reason (a deadline, a cancel by the
// caller) is not an interrupt and keeps the ordinary exit codes.
func interrupted(ctx context.Context) bool {
	return errors.Is(context.Cause(ctx), ErrInterrupted)
}

// writeDocument renders the document into a buffer and writes it to stdout
// only when the run was not interrupted, so an interrupted run never leaves a
// partial document on stdout.
func writeDocument(ctx context.Context, stdout io.Writer, render func(io.Writer) error) error {
	var buffer bytes.Buffer
	if err := render(&buffer); err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	if interrupted(ctx) {
		return &commandError{code: ExitInterrupted}
	}
	if _, err := stdout.Write(buffer.Bytes()); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
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
