package ownsbom

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

const gradleCatalog = "[versions]\nguava = \"32.1.1-jre\"\n\n[libraries]\nguava = { module = \"com.google.guava:guava\", version.ref = \"guava\" }\ncommons = \"org.apache.commons:commons-lang3:3.12.0\"\njunit = { group = \"org.junit.jupiter\", name = \"junit-jupiter\", version = \"5.9.0\" }\n"

// ParseGradleCatalog is the shared parser used by BOTH the owned Gradle parser and the manifest enricher
// . It must resolve all three library notations against the [versions] table.
func TestParseGradleCatalog(t *testing.T) {
	comps := ParseGradleCatalog([]byte(gradleCatalog))
	got := map[string]string{}
	purl := map[string]string{}
	for _, c := range comps {
		got[c.Name] = c.Version
		purl[c.Name] = c.PURL
	}
	if got["com.google.guava:guava"] != "32.1.1-jre" {
		t.Errorf("guava version.ref not resolved: %v", got)
	}
	if got["org.apache.commons:commons-lang3"] != "3.12.0" {
		t.Errorf("commons string-notation not parsed: %v", got)
	}
	if got["org.junit.jupiter:junit-jupiter"] != "5.9.0" {
		t.Errorf("junit inline group/name/version not parsed: %v", got)
	}
	if purl["com.google.guava:guava"] != "pkg:maven/com.google.guava/guava@32.1.1-jre" {
		t.Errorf("resolved library must carry a maven PURL: %v", purl)
	}
}

// The Gradle EcosystemParser wraps ParseGradleCatalog, tagging each component with the catalog file path as
// its Location (the shared parser leaves Location unset for the enricher's no-Location path).
func TestGradleParserSetsLocation(t *testing.T) {
	comps, deps, err := (Gradle{}).Parse(context.Background(), ParseInput{Path: "gradle/libs.versions.toml", Content: []byte(gradleCatalog)})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if deps != nil {
		t.Errorf("the catalog yields components, not edges; got deps %+v", deps)
	}
	if len(comps) == 0 {
		t.Fatal("want components from the catalog")
	}
	for _, c := range comps {
		if c.Location != "gradle/libs.versions.toml" {
			t.Errorf("component %q must carry the catalog Location, got %q", c.Name, c.Location)
		}
		if c.Scope != sbom.ScopeProduction {
			t.Errorf("catalog components default to production scope, got %q for %q", c.Scope, c.Name)
		}
	}
}

func TestGradleParserMarkersAndEcosystem(t *testing.T) {
	g := Gradle{}
	if g.Ecosystem() != "maven" {
		t.Errorf("Gradle deps are maven coordinates; Ecosystem() = %q", g.Ecosystem())
	}
	if len(g.Markers()) != 1 || g.Markers()[0] != "libs.versions.toml" {
		t.Errorf("Gradle must claim the libs.versions.toml marker, got %v", g.Markers())
	}
}

// The default registry must include the Gradle parser without a
// marker collision (New errors on duplicate markers).
func TestDefaultRegistryIncludesGradle(t *testing.T) {
	r, err := DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry must build without a marker collision: %v", err)
	}
	if _, ok := r.byMarker["libs.versions.toml"]; !ok {
		t.Error("the default registry must claim libs.versions.toml (Gradle coverage)")
	}
}
