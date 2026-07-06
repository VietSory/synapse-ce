package manifest

import (
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

type pnpmLock struct {
	Importers map[string]pnpmImporter `yaml:"importers"`
	// Single-package repos (no workspaces) put deps at the top level instead.
	Dependencies    map[string]pnpmDep `yaml:"dependencies"`
	DevDependencies map[string]pnpmDep `yaml:"devDependencies"`
}

type pnpmImporter struct {
	Dependencies         map[string]pnpmDep `yaml:"dependencies"`
	DevDependencies      map[string]pnpmDep `yaml:"devDependencies"`
	OptionalDependencies map[string]pnpmDep `yaml:"optionalDependencies"`
}

// pnpmDep is `{specifier, version}` in pnpm v6+. The version may carry a peer
// suffix like "18.2.0(react@18)"; we keep only the leading version.
type pnpmDep struct {
	Version string `yaml:"version"`
}

// parsePnpmScopes attributes each resolved package (name@version) to a scope by
// which workspace importer declares it (pnpm hoists all workspaces into one root
// lock, losing the per-workspace signal otherwise). A dep declared by a production
// importer is production; one declared only under examples/ or test/ takes that
// scope; devDependencies are development. Returns name@version -> scope for the
// direct deps it can attribute (the common case for stale vulnerable pins).
func parsePnpmScopes(data []byte) map[string]string {
	var lock pnpmLock
	if yaml.Unmarshal(data, &lock) != nil {
		return nil
	}
	best := map[string]string{} // name@version -> most-production scope seen
	consider := func(name string, d pnpmDep, scope string) {
		key := pkgKey(name, d.Version)
		if key == "" {
			return
		}
		if cur, ok := best[key]; !ok || scopeRank(scope) > scopeRank(cur) {
			best[key] = scope
		}
	}
	apply := func(dir string, imp pnpmImporter) {
		base := sbom.ClassifyScope(dir+"/package.json", "")
		prodScope := base
		devScope := base
		if base == sbom.ScopeProduction {
			devScope = sbom.ScopeDevelopment
		}
		for n, d := range imp.Dependencies {
			consider(n, d, prodScope)
		}
		for n, d := range imp.OptionalDependencies {
			consider(n, d, prodScope)
		}
		for n, d := range imp.DevDependencies {
			consider(n, d, devScope)
		}
	}
	if len(lock.Importers) > 0 {
		for dir, imp := range lock.Importers {
			apply(normalizeImporterDir(dir), imp)
		}
	} else {
		apply(".", pnpmImporter{Dependencies: lock.Dependencies, DevDependencies: lock.DevDependencies})
	}
	return best
}

// normalizeImporterDir turns the pnpm importer key (".", "examples/foo") into a
// path ClassifyScope understands.
func normalizeImporterDir(dir string) string {
	if dir == "." || dir == "" {
		return "."
	}
	return dir
}

// pkgKey is the name@version identity, stripping any pnpm peer suffix.
func pkgKey(name, version string) string {
	v := version
	if i := strings.IndexByte(v, '('); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimSpace(v)
	if name == "" || v == "" || !sbom.IsResolvedVersion(v) {
		return ""
	}
	return name + "@" + v
}

// scopeRank orders scopes from most-production (kept) to most-background.
func scopeRank(s string) int {
	switch s {
	case sbom.ScopeProduction:
		return 5
	case sbom.ScopeDevelopment:
		return 4
	case sbom.ScopeUnknown:
		return 3
	case sbom.ScopeBenchmark, sbom.ScopeDocumentation:
		return 2
	default: // test / example / fixture
		return 1
	}
}
