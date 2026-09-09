package ownsbom

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestNPMEdgeScopeAndOptional(t *testing.T) {
	lock := []byte(`{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0"},
    "node_modules/parent": {
      "version": "1.0.0",
      "dependencies": {"runtime": "1.0.0", "shared": "1.0.0"},
      "devDependencies": {"dev-only": "1.0.0", "shared": "1.0.0"},
      "optionalDependencies": {"optional": "1.0.0"}
    },
    "node_modules/runtime": {"version": "1.0.0"},
    "node_modules/dev-only": {"version": "1.0.0"},
    "node_modules/shared": {"version": "1.0.0"},
    "node_modules/optional": {"version": "1.0.0"}
  }
}`)

	_, deps, err := NPM{}.Parse(context.Background(), ParseInput{Path: "package-lock.json", Content: lock})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	ref := "pkg:npm/parent@1.0.0"
	got := map[string]struct {
		scope    string
		optional bool
	}{}
	for _, dependency := range deps {
		if dependency.Ref != ref {
			continue
		}
		for _, target := range dependency.DependsOn {
			got[target] = struct {
				scope    string
				optional bool
			}{dependency.Scope, dependency.Optional}
		}
	}

	want := map[string]struct {
		scope    string
		optional bool
	}{
		"pkg:npm/runtime@1.0.0":  {sbom.ScopeProduction, false},
		"pkg:npm/dev-only@1.0.0": {sbom.ScopeDevelopment, false},
		"pkg:npm/shared@1.0.0":   {sbom.ScopeProduction, false},
		"pkg:npm/optional@1.0.0": {sbom.ScopeProduction, true},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d parent edges, want %d: %#v", len(got), len(want), got)
	}
	for target, expected := range want {
		if got[target] != expected {
			t.Errorf("edge %s -> %s = %#v, want %#v", ref, target, got[target], expected)
		}
	}
}
