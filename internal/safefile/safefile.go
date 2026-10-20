// Package safefile reads local input files under a fixed budget.
//
// Every file scadenza reads from the local disk is untrusted input: it may be
// a device, a named pipe, a symlink to something else, or a file far larger
// than the tool needs. The helpers here open a path, require a regular file,
// and read at most a fixed number of bytes, so one hostile path can neither
// hang the process nor exhaust its memory. The YAML helper decodes one
// document out of such a file under the same rules: exactly one document,
// bounded nesting, and no unknown keys.
package safefile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

// ErrNotRegular marks a path that does not resolve to a regular file.
var ErrNotRegular = errors.New("not a regular file")

// ErrTooLarge marks a file that is larger than the caller's limit.
var ErrTooLarge = errors.New("file is too large")

// Read reads a local file under a byte limit.
//
// The path is used as given, so a symlink is followed and its target is the
// file that is checked and read. The target must be a regular file: a
// directory, a device, a socket, or a named pipe is rejected instead of being
// read, so it can never block the process. At most limit bytes are read, and
// a larger file is an error that names the path and the limit. The error
// never carries the content of the file.
func Read(path string, limit int64) ([]byte, error) {
	// The type is checked before the file is opened: opening a named pipe
	// waits for a writer that may never come.
	info, err := os.Stat(path)
	if err != nil {
		return nil, openError(path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", path, ErrNotRegular)
	}
	//nolint:gosec // G304: the path is the file the caller was asked to read.
	file, err := os.Open(path)
	if err != nil {
		return nil, openError(path, err)
	}
	defer func() { _ = file.Close() }()
	// The path may have been replaced between the check and the open, so the
	// opened file is checked again.
	opened, err := file.Stat()
	if err != nil {
		return nil, openError(path, err)
	}
	if !opened.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", path, ErrNotRegular)
	}
	if opened.Size() > limit {
		return nil, fmt.Errorf("%s: %w: %d bytes exceed the %d byte limit", path, ErrTooLarge, opened.Size(), limit)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: %w: more than the %d byte limit", path, ErrTooLarge, limit)
	}
	return data, nil
}

// openError reports a failed lookup as an open failure, so the message names
// the path once.
func openError(path string, err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return fmt.Errorf("open %s: %w", path, pathErr.Err)
	}
	return fmt.Errorf("open %s: %w", path, err)
}
