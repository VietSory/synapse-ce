package ownsbom

import "testing"

// TestDefaultRegistry asserts the production producer assembles the Tier-1 owned parsers and
// dispatches every ecosystem's marker — so SYNAPSE_SBOM_PRODUCER=ownsbom yields a usable SBOMGenerator.
func TestDefaultRegistry(t *testing.T) {
	reg, err := DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry: %v", err)
	}
	for _, marker := range []string{
		"go.mod", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "requirements-dev.txt", "poetry.lock", "pipfile.lock", "cargo.lock", "pom.xml", "libs.versions.toml", "gemfile.lock", "composer.lock", "packages.lock.json", "package.resolved", "pubspec.lock", "mix.lock",
	} {
		if _, ok := reg.byMarker[marker]; !ok {
			t.Errorf("DefaultRegistry missing marker %q", marker)
		}
	}
	// yarn + pnpm share the npm ecosystem, Pipfile shares pypi, Gradle shares maven, so the distinct set is
	// cargo/composer/gem/go/hex/maven/npm/nuget/pub/pypi/swift (sorted) — unchanged by the new parsers.
	want := []string{"cargo", "composer", "gem", "go", "hex", "maven", "npm", "nuget", "pub", "pypi", "swift"}
	if len(reg.ecos) != len(want) {
		t.Fatalf("DefaultRegistry ecosystems = %v, want %v", reg.ecos, want)
	}
	for i, e := range want {
		if reg.ecos[i] != e {
			t.Errorf("ecosystem[%d] = %q, want %q", i, reg.ecos[i], e)
		}
	}
}
