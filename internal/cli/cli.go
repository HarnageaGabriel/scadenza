// Package cli owns the scadenza command-line interface.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

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

// interruptedMessage is the last line a stopped run writes to stderr. It is
// static text, so it never carries a value from the interrupted run. The
// diagnostics a run printed before the interrupt stay on stderr, so the
// interrupt is the last line and not the only one.
const interruptedMessage = "interrupted"

// ErrInterrupted is the cancellation cause of a run that was stopped by an
// interrupt signal. A context cancelled with this cause ends the run with
// ExitInterrupted and without a report; a context cancelled for any other
// reason keeps the ordinary exit codes.
var ErrInterrupted = errors.New(interruptedMessage)

// ErrDeadlineExceeded is the cancellation cause of a run that reached the
// maximum duration. Unlike an interrupt, a run that reached the limit still
// reports what it collected, so the cause is what tells the two apart.
var ErrDeadlineExceeded = errors.New("deadline exceeded")

// runState holds the facts about a run that the exit code depends on. The
// command body writes them and the exit code reads them, so it is shared by
// pointer.
type runState struct {
	// documentWritten records that the whole document was written to
	// stdout. A run that already wrote its document is complete, so a
	// signal that arrives afterwards does not turn the finished run into an
	// interrupted one.
	documentWritten bool
}

// deadlineContext derives the context the command body works under.
//
// The limit starts when the command body starts working, not at process start,
// so the deadline is derived here. The limit is a cause of its own, so an
// interrupt still wins: the interrupt cancels the run context, and the cause
// propagates to the derived context.
//
// A limit of zero means no limit, and the derived context then only follows
// the run context.
func deadlineContext(ctx context.Context, limit time.Duration) (context.Context, context.CancelFunc) {
	if limit <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeoutCause(ctx, limit, ErrDeadlineExceeded)
}

// deadlineExceeded reports whether the run stopped because it reached the
// maximum duration. A cancellation with any other cause is not a deadline.
func deadlineExceeded(ctx context.Context) bool {
	return errors.Is(context.Cause(ctx), ErrDeadlineExceeded)
}

// Execute runs the CLI and converts command errors to documented exit codes.
func Execute(args []string, stdout, stderr io.Writer) int {
	return ExecuteContext(context.Background(), args, stdout, stderr)
}

// ExecuteContext runs the CLI under the given context and converts command
// errors to documented exit codes. Cancelling the context with ErrInterrupted
// stops the run: no report is written, the last line on stderr is
// `interrupted`, and the run exits with ExitInterrupted.
//
// A run that already wrote its document is complete, so an interrupt that
// arrives after the write keeps the exit code the results decide.
func ExecuteContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return execute(ctx, args, stdout, stderr, productionCTDependencies())
}

// execute runs the command line under the given context and converts its
// errors to documented exit codes. Cobra adds the commands it provides itself
// (help, completion, and the hidden completion request) while it runs, so the
// command line is only checked against the complete command tree after the
// run.
func execute(ctx context.Context, args []string, stdout, stderr io.Writer, dependencies ctDependencies) int {
	if interrupted(ctx) {
		// The run was interrupted before the command body started, so it
		// does nothing at all: no document, and not even the version text
		// or the help text.
		_, _ = fmt.Fprintln(stderr, interruptedMessage)
		return ExitInterrupted
	}
	state := &runState{}
	root := newRootCommand(stdout, stderr, dependencies, state)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if interrupted(ctx) && !state.documentWritten {
		// The run was stopped by a signal before it wrote its document. It
		// reports nothing: a partial document would look like a result.
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
// only when the run was not interrupted; a partial write happens only when
// the write itself fails. The check takes the run context, not the deadline
// context derived from it: once the deadline fired, the derived cause stays
// the deadline cause and would hide a later interrupt on the run context.
//
// The state records that the document was written, so a signal that arrives
// after the write does not change the exit code of a finished run.
func writeDocument(ctx context.Context, stdout io.Writer, state *runState, render func(io.Writer) error) error {
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
	state.documentWritten = true
	return nil
}

// printUsageError writes the usage error of an unknown command the way cobra
// writes it, so the message is the one the command line produced.
func printUsageError(root *cobra.Command, err error) {
	root.PrintErrln(root.ErrPrefix(), err.Error())
	root.PrintErrf("Run '%v --help' for usage.\n", root.CommandPath())
}

func newRootCommand(stdout, stderr io.Writer, dependencies ctDependencies, state *runState) *cobra.Command {
	root := &cobra.Command{
		Use:           "scadenza",
		Short:         "Inspect public TLS certificate readiness",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return &commandError{code: ExitUsageError, err: err} })
	versionCommand := newVersionCommand(stdout, state)
	ctCommand := newCTCommand(stdout, stderr, dependencies, state)
	scanCommand := newScanCommand(stdout, stderr, dependencies, state)
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

func newVersionCommand(stdout io.Writer, state *runState) *cobra.Command {
	var asJSON bool
	command := &cobra.Command{
		Use:   "version",
		Short: "Print build version information",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if interrupted(cmd.Context()) {
				// The run was interrupted before the body started working, so
				// it prints nothing at all, not even the version.
				return &commandError{code: ExitInterrupted}
			}
			info := version.Current()
			if asJSON {
				encoder := json.NewEncoder(stdout)
				encoder.SetEscapeHTML(false)
				if err := encoder.Encode(info); err != nil {
					return err
				}
			} else if _, err := fmt.Fprintf(stdout, "scadenza %s\ncommit: %s\ndate: %s\n", info.Version, info.Commit, info.Date); err != nil {
				return err
			}
			// The version text is the whole document of this command, so a
			// signal after it keeps the exit code of a finished run.
			state.documentWritten = true
			return nil
		},
	}
	command.Flags().BoolVar(&asJSON, "json", false, "print version information as JSON")
	return command
}
