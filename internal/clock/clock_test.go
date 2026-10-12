package clock

import (
	"testing"
	"time"
)

func TestClocks(t *testing.T) {
	want := time.Date(2027, time.March, 15, 0, 0, 0, 0, time.UTC)
	if got := (Fixed{Time: want}).Now(); !got.Equal(want) {
		t.Fatalf("Fixed.Now() = %v, want %v", got, want)
	}
	before := time.Now()
	got := (System{}).Now()
	after := time.Now()
	if got.Before(before) || got.After(after) {
		t.Fatalf("System.Now() = %v, want between %v and %v", got, before, after)
	}
}
