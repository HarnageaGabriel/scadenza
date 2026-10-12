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
)

// Execute runs the CLI and converts command errors to documented exit codes.
func Execute(args []string, stdout, stderr io.Writer) int {
	return execute(args, stdout, stderr, productionCTDependencies())
}

func execute(args []string, stdout, stderr io.Writer, dependencies ctDependencies) int {
	root := newRootCommand(stdout, stderr, dependencies)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		return exitCode(err)
	}
	return ExitOK
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
	root.AddCommand(newVersionCommand(stdout))
	root.AddCommand(newCTCommand(stdout, stderr, dependencies))
	return root
}

func newVersionCommand(stdout io.Writer) *cobra.Command {
	var asJSON bool
	command := &cobra.Command{
		Use:   "version",
		Short: "Print build version information",
		Args:  cobra.NoArgs,
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
