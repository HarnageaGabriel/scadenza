// Package clock is the sole owner of wall-clock access.
package clock

import "time"

// Clock provides the current time.
type Clock interface {
	Now() time.Time
}

// System reads the system wall clock.
type System struct{}

// Now returns the current system time.
func (System) Now() time.Time { return time.Now() }

// Fixed always returns a configured time.
type Fixed struct {
	Time time.Time
}

// Now returns the fixed time.
func (f Fixed) Now() time.Time { return f.Time }
