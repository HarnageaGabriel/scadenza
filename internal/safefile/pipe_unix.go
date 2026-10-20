//go:build unix && !aix && !solaris && !illumos

package safefile

import "syscall"

// CreatePipe creates a named pipe at path. It exists so that the tests of the
// readers can prove that a pipe is rejected instead of read.
func CreatePipe(path string) error {
	return syscall.Mkfifo(path, 0o600)
}
