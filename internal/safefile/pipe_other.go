//go:build !unix || aix || solaris || illumos

package safefile

import "errors"

// CreatePipe reports that this platform has no named pipes.
func CreatePipe(string) error {
	return errors.New("named pipes are not available on this platform")
}
