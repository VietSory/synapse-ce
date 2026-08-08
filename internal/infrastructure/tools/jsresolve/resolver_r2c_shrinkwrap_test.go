package jsresolve

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestResolverR2CNPM11ShrinkwrapPrecedesPackageLock(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "npm@11.6.0",
		"dependencies":   map[string]string{"lodash": "^4"},
	})
	writeNPMResolvedLock(t, r2bJoin(root, "package-lock.json"), "lodash", "4.17.20")
	writeNPMResolvedLock(t, r2bJoin(root, "npm-shrinkwrap.json"), "lodash", "4.17.21")
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "lodash", Version: "4.17.20", PURL: "pkg:npm/lodash@4.17.20"},
		{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"},
	}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusComponent || got.Imports[0].Package.PURL != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("npm 11 did not prefer shrinkwrap: %#v coverage=%#v", got.Imports[0], got.Coverage)
	}
}

func TestResolverR2CNPM12IgnoresShrinkwrap(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "npm@12.1.0",
		"dependencies":   map[string]string{"lodash": "^4"},
	})
	writeNPMResolvedLock(t, r2bJoin(root, "package-lock.json"), "lodash", "4.17.20")
	writeNPMResolvedLock(t, r2bJoin(root, "npm-shrinkwrap.json"), "lodash", "4.17.21")
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "lodash", Version: "4.17.20", PURL: "pkg:npm/lodash@4.17.20"},
		{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"},
	}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusComponent || got.Imports[0].Package.PURL != "pkg:npm/lodash@4.17.20" {
		t.Fatalf("npm 12 did not ignore shrinkwrap: %#v coverage=%#v", got.Imports[0], got.Coverage)
	}
}

func TestResolverR2CShrinkwrapWithoutNPMMajorFailsClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":         "root",
		"dependencies": map[string]string{"lodash": "^4"},
	})
	writeNPMResolvedLock(t, r2bJoin(root, "npm-shrinkwrap.json"), "lodash", "4.17.21")
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Complete || got.Imports[0].Status == jsresolution.StatusComponent {
		t.Fatalf("version-unknown shrinkwrap produced false confidence: %#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedPackageManager) {
		t.Fatalf("version-unknown shrinkwrap lacks package-manager coverage: %#v", got.Coverage)
	}
}

func writeNPMResolvedLock(t *testing.T, filename, name, version string) {
	t.Helper()
	writeJSON(t, filename, map[string]any{
		"lockfileVersion": 3,
		"packages": map[string]any{
			"":                     map[string]any{"dependencies": map[string]string{name: "^4"}},
			"node_modules/" + name: map[string]any{"version": version},
		},
	})
}
