package jsresolve

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestMaintainerAuditYarnResolutionVersionMismatchFailsClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "yarn@4.9.0",
		"dependencies":   map[string]string{"lodash": "4.17.21"},
	})
	writeFile(t, r2bJoin(root, "yarn.lock"), `__metadata:
  version: 8

"lodash@npm:4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.20"
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusComponent || got.Complete {
		t.Fatalf("Yarn resolution/version mismatch became definitive: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedMetadata) {
		t.Fatalf("Yarn resolution/version mismatch lacks unsupported-metadata coverage: %#v", got.Coverage)
	}
}

func TestMaintainerAuditYarnDuplicateDescriptorWithOneBadLocatorFailsClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "yarn@4.9.0",
		"dependencies":   map[string]string{"lodash": "4.17.21"},
	})
	writeFile(t, r2bJoin(root, "yarn.lock"), `__metadata:
  version: 8

"lodash@npm:4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"

"lodash@npm:4.17.21":
  version: 4.17.21
  resolution: "evil@npm:4.17.21"
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusComponent || got.Complete {
		t.Fatalf("a good duplicate descriptor washed out a bad Yarn locator: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedMetadata) {
		t.Fatalf("duplicate descriptor conflict lacks unsupported-metadata coverage: %#v", got.Coverage)
	}
}

func TestMaintainerAuditYarnScopedNPMResolutionCorrelates(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "yarn@4.9.0",
		"dependencies":   map[string]string{"@scope/pkg": "1.2.3"},
	})
	writeFile(t, r2bJoin(root, "yarn.lock"), `__metadata:
  version: 8

"@scope/pkg@npm:1.2.3":
  version: 1.2.3
  resolution: "@scope/pkg@npm:1.2.3"
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "@scope/pkg", Version: "1.2.3", PURL: "pkg:npm/%40scope/pkg@1.2.3"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "@scope/pkg/subpath"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusComponent || got.Imports[0].Package.PURL != "pkg:npm/%40scope/pkg@1.2.3" || !got.Complete {
		t.Fatalf("valid scoped Yarn npm locator was not correlated: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
}

func TestMaintainerAuditYarnSameNameWorkspaceWithExactNPMRequestIsNotForcedExternal(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "yarn@4.9.0",
		"workspaces":     []string{"packages/*"},
		"dependencies":   map[string]string{"shared": "npm:1.0.0"},
	})
	writeJSON(t, r2bJoin(root, "packages/shared/package.json"), map[string]any{"name": "shared", "version": "1.0.0"})
	writeFile(t, r2bJoin(root, "yarn.lock"), `__metadata:
  version: 8

"shared@npm:1.0.0":
  version: 1.0.0
  resolution: "shared@npm:1.0.0"
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "shared", Version: "1.0.0", PURL: "pkg:npm/shared@1.0.0"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "shared"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusComponent || got.Complete {
		t.Fatalf("same-name matching Yarn workspace was incorrectly forced to registry component: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if got.Imports[0].Status != jsresolution.StatusAmbiguous {
		t.Fatalf("same-name Yarn workspace should remain explicit ambiguity, got %#v", got.Imports[0])
	}
}

func TestMaintainerAuditYarnUnrelatedBadLocatorKeepsPositiveButMakesCoverageIncomplete(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "yarn@4.9.0",
		"dependencies":   map[string]string{"lodash": "4.17.21"},
	})
	writeFile(t, r2bJoin(root, "yarn.lock"), `__metadata:
  version: 8

"lodash@npm:4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"

"evil@npm:1.0.0":
  version: 1.0.0
  resolution: "other@npm:1.0.0"
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusComponent || got.Imports[0].Package.PURL != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("unrelated invalid Yarn metadata destroyed a valid positive component: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if got.Complete {
		t.Fatalf("invalid observed Yarn metadata was silently ignored: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedMetadata) && !hasCoverageKind(got.Coverage, jsresolution.CoverageMalformedMetadata) {
		t.Fatalf("invalid observed Yarn metadata lacks explicit coverage: %#v", got.Coverage)
	}
}
