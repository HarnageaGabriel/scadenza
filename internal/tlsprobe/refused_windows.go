//go:build windows

package tlsprobe

import "syscall"

// refusedErrno is WSAECONNREFUSED, which Winsock reports as errno 10061. The
// POSIX-named syscall.ECONNREFUSED is an invented constant on Windows that
// Winsock never returns, so the numeric Winsock code is named here.
const refusedErrno syscall.Errno = 10061
