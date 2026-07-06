package ownsbom

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

const nugetLockFixture = `{
  "version": 1,
  "dependencies": {
    "net6.0": {
      "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"},
      "Serilog": {"type": "Transitive", "resolved": "2.12.0"},
      "MyApp.Core": {"type": "Project"}
    },
    "net8.0": {
      "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"},
      "Polly": {"type": "Transitive", "resolved": "7.2.4"}
    }
  }
}`

func TestNuGetParse(t *testing.T) {
	comps, deps, err := NuGet{}.Parse(context.Background(), ParseInput{Path: "packages.lock.json", Content: []byte(nugetLockFixture)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if deps != nil {
		t.Errorf("edges not emitted; want nil deps, got %v", deps)
	}
	byName := map[string]sbom.Component{}
	for _, c := range comps {
		byName[c.Name] = c
	}
	// Newtonsoft.Json (same version under both TFMs) dedups → 1; + Serilog + Polly = 3. The Project ref skipped.
	if len(comps) != 3 {
		t.Fatalf("want 3 components (Newtonsoft dedup, Project skipped), got %d (%+v)", len(comps), comps)
	}
	if _, ok := byName["MyApp.Core"]; ok {
		t.Error("a Project reference must not be emitted as a nuget package")
	}
	if c := byName["Newtonsoft.Json"]; c.PURL != "pkg:nuget/Newtonsoft.Json@13.0.1" {
		t.Errorf("PURL wrong: %+v", c)
	}
	if _, ok := byName["Polly"]; !ok {
		t.Error("a Transitive package must be emitted")
	}
}

func TestNuGetParseDeterministic(t *testing.T) {
	// packages.lock.json's per-framework maps have no inherent order; the parser sorts by PURL so the output
	// is stable across runs (Go randomizes map iteration).
	c1, _, _ := NuGet{}.Parse(context.Background(), ParseInput{Path: "packages.lock.json", Content: []byte(nugetLockFixture)})
	c2, _, _ := NuGet{}.Parse(context.Background(), ParseInput{Path: "packages.lock.json", Content: []byte(nugetLockFixture)})
	if len(c1) != len(c2) {
		t.Fatalf("length mismatch %d vs %d", len(c1), len(c2))
	}
	for i := range c1 {
		if c1[i].PURL != c2[i].PURL {
			t.Errorf("order not deterministic at %d: %q vs %q", i, c1[i].PURL, c2[i].PURL)
		}
	}
}

func TestNuGetParseMalformed(t *testing.T) {
	if _, _, err := (NuGet{}).Parse(context.Background(), ParseInput{Path: "packages.lock.json", Content: []byte("{bad")}); err == nil {
		t.Error("malformed packages.lock.json must fail loud")
	}
}
