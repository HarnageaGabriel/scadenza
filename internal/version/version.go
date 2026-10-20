// Package version exposes build metadata set with linker flags.
package version

import "runtime/debug"

// The default values mark a field that no linker flag has set. A field that
// still holds its default may be filled from the build information the Go
// toolchain embeds in the binary.
const (
	defaultVersion = "dev"
	defaultCommit  = "unknown"
	defaultDate    = "unknown"
)

// These values are replaced by release builds using -ldflags -X.
var (
	Version = defaultVersion
	Commit  = defaultCommit
	Date    = defaultDate
)

// readBuildInfo returns the build information the Go toolchain embedded in the
// binary. It is a variable so tests can inject a fake instead of the build
// information of the test binary itself.
var readBuildInfo = debug.ReadBuildInfo

// Info is the stable JSON representation of build metadata.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

// Current returns the current build metadata. A value set by a linker flag
// always wins; a field that still holds its default is filled from the build
// information when it provides one.
func Current() Info {
	info := Info{Version: Version, Commit: Commit, Date: Date}
	build, ok := readBuildInfo()
	if !ok || build == nil {
		return info
	}
	if info.Version == defaultVersion {
		if moduleVersion := buildVersion(build); moduleVersion != "" {
			info.Version = moduleVersion
		}
	}
	if info.Commit == defaultCommit {
		if revision := buildCommit(build); revision != "" {
			info.Commit = revision
		}
	}
	if info.Date == defaultDate {
		if stamp := buildSetting(build, "vcs.time"); stamp != "" {
			info.Date = stamp
		}
	}
	return info
}

// buildVersion returns the main module version recorded in the build
// information. The toolchain reports "(devel)" for a build that has no module
// version, which carries no information and is therefore not used.
func buildVersion(build *debug.BuildInfo) string {
	if build.Main.Version == "" || build.Main.Version == "(devel)" {
		return ""
	}
	return build.Main.Version
}

// buildCommit returns the revision recorded in the build information. A
// modified working tree is marked so the commit text says the binary was not
// built from that exact tree.
func buildCommit(build *debug.BuildInfo) string {
	revision := buildSetting(build, "vcs.revision")
	if revision == "" {
		return ""
	}
	if buildSetting(build, "vcs.modified") == "true" {
		return revision + "+dirty"
	}
	return revision
}

// buildSetting returns the value of a build setting, or an empty string when
// the setting is absent.
func buildSetting(build *debug.BuildInfo, key string) string {
	for _, setting := range build.Settings {
		if setting.Key == key {
			return setting.Value
		}
	}
	return ""
}
