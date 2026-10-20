package main

import (
	"context"
	"os/signal"

	"github.com/HarnageaGabriel/scadenza/internal/cli"
)

// signalContext returns the context the command runs under, and the function
// that stops the signal notification when the run ends.
//
// The context is cancelled when the process is interrupted, and the
// cancellation cause is cli.ErrInterrupted. The cause is what tells an
// interrupt apart from any other cancellation, so a stopped run reports the
// interrupt instead of a partial result.
func signalContext() (context.Context, func()) {
	root, cancel := context.WithCancelCause(context.Background())
	interrupted, stop := signal.NotifyContext(root, interruptSignals()...)
	go func() {
		<-interrupted.Done()
		// The context is already cancelled when the run ended normally, so
		// only a signal gives the interrupt cause.
		if root.Err() == nil {
			cancel(cli.ErrInterrupted)
		}
	}()
	return root, func() {
		cancel(context.Canceled)
		stop()
	}
}
