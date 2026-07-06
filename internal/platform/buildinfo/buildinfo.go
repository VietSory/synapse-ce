// Package buildinfo reports dependency + application versions from the compiled
// binary's build metadata, used to record scan reproducibility.
package buildinfo

import "runtime/debug"

// Module returns the version of the dependency at the given module path (honoring
// a replace directive), or "unknown" if it is not in the build graph.
func Module(path string) string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, d := range bi.Deps {
		if d.Path != path {
			continue
		}
		if d.Replace != nil && d.Replace.Version != "" {
			return d.Replace.Version
		}
		if d.Version != "" {
			return d.Version
		}
	}
	return "unknown"
}

// App returns the main module's version ("devel" for an untagged build, e.g. go run).
func App() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok || bi.Main.Version == "" || bi.Main.Version == "(devel)" {
		return "devel"
	}
	return bi.Main.Version
}
