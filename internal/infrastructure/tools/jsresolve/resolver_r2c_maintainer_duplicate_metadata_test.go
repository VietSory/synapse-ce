package jsresolve

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestMaintainerAuditNPMDuplicatePackagePathFailsClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "npm@10.8.2",
	})
	writeFile(t, r2bJoin(root, "package-lock.json"), `{
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"lodash": "^4"}},
    "node_modules/lodash": {"version": "4.17.20"},
    "node_modules/lodash": {"version": "4.17.21"}
  }
}`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusComponent || got.Complete {
		t.Fatalf("duplicate npm package path became definitive: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageMalformedMetadata) {
		t.Fatalf("duplicate npm package path lacks malformed-metadata coverage: %#v", got.Coverage)
	}
}

func TestMaintainerAuditYarnDuplicateResolutionFieldFailsClosed(t *testing.T) {
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
  resolution: "evil@npm:4.17.21"
  resolution: "lodash@npm:4.17.21"
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusComponent || got.Complete {
		t.Fatalf("duplicate Yarn resolution field became definitive: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageMalformedMetadata) && !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedMetadata) {
		t.Fatalf("duplicate Yarn resolution field lacks explicit coverage: %#v", got.Coverage)
	}
}

func TestMaintainerAuditPNPMDuplicateLockfileVersionFailsClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "pnpm@10.15.0",
		"dependencies":   map[string]string{"lodash": "4.17.21"},
	})
	writeFile(t, r2bJoin(root, "pnpm-lock.yaml"), `lockfileVersion: '99.0'
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      lodash:
        specifier: 4.17.21
        version: 4.17.21
packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-valid}
snapshots:
  lodash@4.17.21: {}
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusComponent || got.Complete {
		t.Fatalf("duplicate pnpm lockfileVersion became definitive: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageMalformedMetadata) && !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedMetadata) {
		t.Fatalf("duplicate pnpm lockfileVersion lacks explicit coverage: %#v", got.Coverage)
	}
}
