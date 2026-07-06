package ownsbom

import (
	"context"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

const goModFixture = `module github.com/example/app

go 1.26

toolchain go1.26.0

require (
	github.com/sirupsen/logrus v1.9.3
	golang.org/x/sync v0.7.0 // indirect
)

require github.com/spf13/cobra v1.8.0

replace github.com/old/x => github.com/new/x v1.0.0

exclude github.com/bad/y v0.1.0
`

func TestGoModParse(t *testing.T) {
	comps, deps, err := GoMod{}.Parse(context.Background(), ParseInput{Path: "go.mod", Content: []byte(goModFixture)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if deps != nil {
		t.Errorf("go.mod alone has no edge graph; want nil deps, got %v", deps)
	}
	if len(comps) != 3 {
		t.Fatalf("want 3 components, got %d: %+v", len(comps), comps)
	}
	got := map[string]string{}
	for _, c := range comps {
		got[c.Name] = c.Version
		if !strings.HasPrefix(c.PURL, "pkg:golang/") || c.PURL != "pkg:golang/"+c.Name+"@"+c.Version {
			t.Errorf("PURL %q malformed for %s@%s", c.PURL, c.Name, c.Version)
		}
		// C-3: components carry the manifest location + derived scope (parity with the Syft path), not unscoped
		if c.Location != "go.mod" || c.Scope != sbom.ScopeProduction {
			t.Errorf("component %s location/scope = %q/%q, want go.mod/production", c.Name, c.Location, c.Scope)
		}
	}
	// block requires (direct + indirect) + the single-line require are all captured
	for name, ver := range map[string]string{
		"github.com/sirupsen/logrus": "v1.9.3",
		"golang.org/x/sync":          "v0.7.0", // // indirect comment stripped, still counted
		"github.com/spf13/cobra":     "v1.8.0", // single-line require
	} {
		if got[name] != ver {
			t.Errorf("component %s = %q, want %q (all: %+v)", name, got[name], ver, got)
		}
	}
	// the module's own path, replace targets, and exclude entries are NOT components
	for _, absent := range []string{"github.com/example/app", "github.com/new/x", "github.com/old/x", "github.com/bad/y"} {
		if _, ok := got[absent]; ok {
			t.Errorf("%s must not be emitted as a component", absent)
		}
	}
}
