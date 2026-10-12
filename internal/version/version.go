// Package version exposes build metadata set with linker flags.
package version

// These values are replaced by release builds using -ldflags -X.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// Info is the stable JSON representation of build metadata.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

// Current returns the current build metadata.
func Current() Info {
	return Info{Version: Version, Commit: Commit, Date: Date}
}
