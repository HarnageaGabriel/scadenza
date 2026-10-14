//go:build !windows

package tlsprobe

import "syscall"

// refusedErrno is the errno a refused TCP connection reports on this platform.
const refusedErrno syscall.Errno = syscall.ECONNREFUSED
