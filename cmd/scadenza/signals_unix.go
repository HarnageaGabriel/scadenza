//go:build unix

package main

import (
	"os"
	"syscall"
)

// interruptSignals returns the signals that stop the run: the interrupt
// signal and the termination signal a CI system sends when it cancels a job.
func interruptSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}
