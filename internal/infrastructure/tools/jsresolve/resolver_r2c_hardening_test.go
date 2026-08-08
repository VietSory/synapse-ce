package jsresolve

import (
	"context"
	"fmt"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestResolverR2CLockSelectionStopsAtNearestPackageBoundary(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "npm@11.0.0",
		"dependencies":   map[string]string{"lodash": "4.17.21"},
	})
	writeJSON(t, r2bJoin(root, "tools", "plugin", "package.json"), map[string]any{
		"name":         "plugin",
		"dependencies": map[string]string{"lodash": "3.10.1"},
	})
	writeJSON(t, r2bJoin(root, "package-lock.json"), map[string]any{
		"lockfileVersion": 3,
		"packages": map[string]any{
			"":                    map[string]any{"dependencies": map[string]string{"lodash": "4.17.21"}},
			"node_modules/lodash": map[string]any{"version": "4.17.21"},
		},
	})
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "lodash", Version: "3.10.1", PURL: "pkg:npm/lodash@3.10.1"},
		{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"},
	}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("tools/plugin/src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusAmbiguous || len(got.Imports[0].Candidates) != 2 {
		t.Fatalf("root lock leaked through nested package boundary: %#v coverage=%#v", got.Imports[0], got.Coverage)
	}
}

func TestResolverR2CMalformedPackageLockBindingCannotBecomeComplete(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "npm@11.0.0",
		"dependencies":   map[string]string{"lodash": "^4"},
	})
	writeJSON(t, r2bJoin(root, "package-lock.json"), map[string]any{
		"lockfileVersion": 3,
		"packages": map[string]any{
			"": map[string]any{"dependencies": map[string]string{"lodash": "^4"}},
			// Intentionally no node_modules/lodash target.
		},
	})
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Complete {
		t.Fatalf("malformed lock binding reported complete: %#v", got)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageMalformedMetadata) && !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedMetadata) {
		t.Fatalf("malformed lock binding has no explicit coverage: %#v", got.Coverage)
	}
}

func TestResolverR2CPNPMMissingResolvedVersionCannotBecomeComplete(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "pnpm@10.0.0",
		"dependencies":   map[string]string{"lodash": "^4"},
	})
	writeFile(t, r2bJoin(root, "pnpm-lock.yaml"), `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      lodash:
        specifier: ^4
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Complete {
		t.Fatalf("pnpm importer missing resolved version reported complete: %#v", got)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageMalformedMetadata) && !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedMetadata) {
		t.Fatalf("pnpm missing resolved version has no explicit coverage: %#v", got.Coverage)
	}
}

func TestResolverR2CYarnMissingDescriptorCannotBecomeComplete(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "yarn@1.22.22",
		"dependencies":   map[string]string{"lodash": "^4"},
	})
	writeFile(t, r2bJoin(root, "yarn.lock"), `other@1.0.0:
  version "1.0.0"
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Complete {
		t.Fatalf("missing yarn descriptor reported complete: %#v", got)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedMetadata) && !hasCoverageKind(got.Coverage, jsresolution.CoverageMalformedMetadata) {
		t.Fatalf("missing yarn descriptor has no explicit coverage: %#v", got.Coverage)
	}
}

func TestResolverR2CYarnNestedVersionFieldCannotBecomeResolvedVersion(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "yarn@1.22.22",
		"dependencies":   map[string]string{"lodash": "^4"},
	})
	writeFile(t, r2bJoin(root, "yarn.lock"), `lodash@^4:
  dependencies:
    version: "3.10.1"
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "3.10.1", PURL: "pkg:npm/lodash@3.10.1"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusComponent || got.Complete {
		t.Fatalf("nested yarn version field became a definitive component: %#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedMetadata) {
		t.Fatalf("nested yarn version field has no fail-closed coverage: %#v", got.Coverage)
	}
}

func TestResolverR2CYarnNonRegistryProtocolCannotMasqueradeAsNPMComponent(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "yarn@4.9.0",
		"dependencies":   map[string]string{"local-lib": "file:../local-lib"},
	})
	writeFile(t, r2bJoin(root, "yarn.lock"), `"local-lib@file:../local-lib":
  version: 1.0.0
  resolution: "local-lib@file:../local-lib"
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "local-lib", Version: "1.0.0", PURL: "pkg:npm/local-lib@1.0.0"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "local-lib"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusComponent && got.Complete {
		t.Fatalf("non-registry yarn protocol became a definitive npm component: %#v", got)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedMetadata) {
		t.Fatalf("non-registry yarn protocol has no unsupported coverage: %#v", got.Coverage)
	}
}

func TestBuildNPMComponentIndexCapsCoverageBeforeNormalization(t *testing.T) {
	t.Parallel()
	limits := defaultResolverLimits()
	limits.maxCoverageIssues = 4
	limits.maxSBOMComponents = 64
	doc := &sbom.SBOM{}
	for i := 0; i < 32; i++ {
		doc.Components = append(doc.Components, sbom.Component{
			Name:    "@scope/pkg",
			Version: "1.0.0",
			PURL:    fmt.Sprintf("pkg:npm/@scope/pkg@1.0.%d", i),
		})
	}
	idx, err := buildNPMComponentIndex(context.Background(), doc, limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.coverage) > limits.maxCoverageIssues {
		t.Fatalf("component-index coverage escaped cap: got %d want <= %d", len(idx.coverage), limits.maxCoverageIssues)
	}
	if !hasCoverageKind(idx.coverage, jsresolution.CoverageMetadataBudgetExceeded) {
		t.Fatalf("coverage truncation is not explicit: %#v", idx.coverage)
	}
}

func TestParseNPMComponentPURLRejectsEncodedNamespaceSeparator(t *testing.T) {
	t.Parallel()
	if _, _, err := parseNPMComponentPURL("pkg:npm/%40scope%2Fpkg@1.2.3"); err == nil {
		t.Fatal("non-canonical encoded namespace separator was accepted")
	}
}
