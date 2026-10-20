package version

import (
	"runtime/debug"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCurrent(t *testing.T) {
	stubBuildInfo(t, nil, false)
	want := Info{Version: defaultVersion, Commit: defaultCommit, Date: defaultDate}
	if diff := cmp.Diff(want, Current()); diff != "" {
		t.Fatalf("Current() mismatch (-want +got):\n%s", diff)
	}
}

func TestCurrentUsesBuildInfo(t *testing.T) {
	clean := []debug.BuildSetting{
		{Key: "vcs.revision", Value: "1f0c3a2b1d4e5f60718293a4b5c6d7e8f9012345"},
		{Key: "vcs.time", Value: "2026-01-02T03:04:05Z"},
		{Key: "vcs.modified", Value: "false"},
	}
	defaults := Info{Version: defaultVersion, Commit: defaultCommit, Date: defaultDate}
	tests := []struct {
		name    string
		linker  Info
		build   *debug.BuildInfo
		present bool
		want    Info
	}{
		{
			name:    "no build information keeps the defaults",
			linker:  defaults,
			present: false,
			want:    defaults,
		},
		{
			name:   "tag version and clean tree",
			linker: defaults,
			build: &debug.BuildInfo{
				Main:     debug.Module{Version: "v0.1.0"},
				Settings: clean,
			},
			present: true,
			want:    Info{Version: "v0.1.0", Commit: "1f0c3a2b1d4e5f60718293a4b5c6d7e8f9012345", Date: "2026-01-02T03:04:05Z"},
		},
		{
			name:   "pseudo version and modified tree",
			linker: defaults,
			build: &debug.BuildInfo{
				Main:     debug.Module{Version: "v0.1.1-0.20260102030405-1f0c3a2b1d4e"},
				Settings: []debug.BuildSetting{clean[0], clean[1], {Key: "vcs.modified", Value: "true"}},
			},
			present: true,
			want:    Info{Version: "v0.1.1-0.20260102030405-1f0c3a2b1d4e", Commit: "1f0c3a2b1d4e5f60718293a4b5c6d7e8f9012345+dirty", Date: "2026-01-02T03:04:05Z"},
		},
		{
			name:   "devel module version keeps the default version",
			linker: defaults,
			build: &debug.BuildInfo{
				Main:     debug.Module{Version: "(devel)"},
				Settings: clean,
			},
			present: true,
			want:    Info{Version: defaultVersion, Commit: "1f0c3a2b1d4e5f60718293a4b5c6d7e8f9012345", Date: "2026-01-02T03:04:05Z"},
		},
		{
			name:   "linker flags win over the build information",
			linker: Info{Version: "1.2.3", Commit: "deadbeef", Date: "2026-02-03T04:05:06Z"},
			build: &debug.BuildInfo{
				Main:     debug.Module{Version: "v0.1.0"},
				Settings: clean,
			},
			present: true,
			want:    Info{Version: "1.2.3", Commit: "deadbeef", Date: "2026-02-03T04:05:06Z"},
		},
		{
			name:   "missing settings keep the defaults",
			linker: defaults,
			build: &debug.BuildInfo{
				Main: debug.Module{Version: "v0.2.0"},
			},
			present: true,
			want:    Info{Version: "v0.2.0", Commit: defaultCommit, Date: defaultDate},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setLinkerValues(t, test.linker)
			stubBuildInfo(t, test.build, test.present)
			if diff := cmp.Diff(test.want, Current()); diff != "" {
				t.Fatalf("Current() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// stubBuildInfo replaces the build information reader for the duration of the
// test.
func stubBuildInfo(t *testing.T, build *debug.BuildInfo, present bool) {
	t.Helper()
	original := readBuildInfo
	t.Cleanup(func() { readBuildInfo = original })
	readBuildInfo = func() (*debug.BuildInfo, bool) { return build, present }
}

// setLinkerValues sets the values a release build would pass with -ldflags -X
// and restores the defaults when the test ends.
func setLinkerValues(t *testing.T, values Info) {
	t.Helper()
	originalVersion, originalCommit, originalDate := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = originalVersion, originalCommit, originalDate })
	Version, Commit, Date = values.Version, values.Commit, values.Date
}
