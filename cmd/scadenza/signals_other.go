//go:build !unix

package main

import "os"

// interruptSignals returns the signals that stop the run. Windows has no
// termination signal, so only the interrupt signal is handled.
func interruptSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}
