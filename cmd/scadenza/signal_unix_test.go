//go:build unix

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/cli"
)

// secondSignalChild is the environment variable that marks the child process
// of TestSecondSignalIsFatal.
const secondSignalChild = "SCADENZA_SECOND_SIGNAL_CHILD"

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

// TestSecondSignalIsFatal proves that the first signal stops the run and
// that the second one ends the process: the notification is stopped after the
// first signal, so the default disposition of the signal returns.
//
// The signal is sent to a child process, because the default disposition of
// SIGINT ends the process that receives it. The child sends the signal again
// and again, so the check does not depend on the moment the notification is
// stopped.
func TestSecondSignalIsFatal(t *testing.T) {
	if os.Getenv(secondSignalChild) == "1" {
		secondSignalProcess()
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestSecondSignalIsFatal$")
	command.Env = append(os.Environ(), secondSignalChild+"=1")
	err := command.Run()
	if err == nil {
		t.Fatal("the child process ended normally: the second signal was not fatal")
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("the child process failed: %v", err)
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("the child process status is not a wait status: %v", err)
	}
	if !status.Signaled() || status.Signal() != syscall.SIGINT {
		t.Fatalf("the child process was not killed by SIGINT: %v", err)
	}
}

// secondSignalProcess is the child of TestSecondSignalIsFatal. It stops the
// run with a first signal and then keeps sending signals until the default
// disposition of the signal kills it.
func secondSignalProcess() {
	ctx, stop := signalContext()
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		os.Exit(2)
	}
	select {
	case <-ctx.Done():
	case <-time.After(10 * time.Second):
		os.Exit(3)
	}
	deadline := time.After(10 * time.Second)
	for {
		if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
			os.Exit(4)
		}
		select {
		case <-deadline:
			// The signal never became fatal, so the notification was not
			// stopped after the first signal.
			os.Exit(5)
		case <-time.After(20 * time.Millisecond):
		}
	}
}
