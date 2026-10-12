package version

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCurrent(t *testing.T) {
	want := Info{Version: Version, Commit: Commit, Date: Date}
	if diff := cmp.Diff(want, Current()); diff != "" {
		t.Fatalf("Current() mismatch (-want +got):\n%s", diff)
	}
}
