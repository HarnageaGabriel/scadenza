//go:build unix

package main

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/cli"
)

// TestSignalContextCancelsOnInterrupt proves that an interrupt signal stops
// the run: the context is cancelled and its cause is cli.ErrInterrupted, so
// the command reports the interrupt instead of a partial result.
//
// The signal is sent to the test process itself. The notification is
// registered before the signal is sent, so the runtime delivers it to the
// context instead of ending the process.
func TestSignalContextCancelsOnInterrupt(t *testing.T) {
	ctx, stop := signalContext()
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Skipf("cannot send SIGINT to this process: %v", err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the interrupt did not cancel the context")
	}
	if cause := context.Cause(ctx); !errors.Is(cause, cli.ErrInterrupted) {
		t.Fatalf("cause = %v, want %v", cause, cli.ErrInterrupted)
	}
}
