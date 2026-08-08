package jsresolve

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestMaintainerAuditPNPMDanglingImporterVersionFailsClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "pnpm@10.15.0",
		"dependencies":   map[string]string{"lodash": "4.17.21"},
	})
	writeFile(t, r2bJoin(root, "pnpm-lock.yaml"), `lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      lodash:
        specifier: 4.17.21
        version: 4.17.21

packages:
  lodash@4.17.20:
    resolution: {integrity: sha512-not-the-imported-version}

snapshots:
  lodash@4.17.20: {}
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusComponent || got.Complete {
		t.Fatalf("dangling pnpm importer version became definitive: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedMetadata) && !hasCoverageKind(got.Coverage, jsresolution.CoverageMalformedMetadata) {
		t.Fatalf("dangling pnpm importer lacks explicit fail-closed coverage: %#v", got.Coverage)
	}
}

func TestMaintainerAuditPNPMV9PackageIdentityCorrelates(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "pnpm@10.15.0",
		"dependencies":   map[string]string{"lodash": "4.17.21"},
	})
	writeFile(t, r2bJoin(root, "pnpm-lock.yaml"), `lockfileVersion: '9.0'
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
	if got.Imports[0].Status != jsresolution.StatusComponent || got.Imports[0].Package.PURL != "pkg:npm/lodash@4.17.21" || !got.Complete {
		t.Fatalf("valid pnpm v9 package identity was not correlated: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
}

func TestMaintainerAuditPNPMUnknownLockVersionFailsClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "pnpm@99.0.0",
		"dependencies":   map[string]string{"lodash": "4.17.21"},
	})
	writeFile(t, r2bJoin(root, "pnpm-lock.yaml"), `lockfileVersion: '99.0'
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
		t.Fatalf("unknown pnpm lockfile version became definitive: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedMetadata) {
		t.Fatalf("unknown pnpm lockfile version lacks unsupported-metadata coverage: %#v", got.Coverage)
	}
}

func TestMaintainerAuditPNPMV9EnvironmentDocumentPrefixCorrelatesMainLock(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "pnpm@11.0.0",
		"dependencies":   map[string]string{"lodash": "4.17.21"},
	})
	writeFile(t, r2bJoin(root, "pnpm-lock.yaml"), `---
lockfileVersion: env-1.0
importers:
  .:
    configDependencies:
      typescript: 5.0.0
---
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
	if got.Imports[0].Status != jsresolution.StatusComponent || got.Imports[0].Package.PURL != "pkg:npm/lodash@4.17.21" || !got.Complete {
		t.Fatalf("current pnpm env-document prefix was not correlated from the main v9 lock document: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
}

func TestMaintainerAuditPNPMV9MissingSnapshotFailsClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "pnpm@10.15.0",
		"dependencies":   map[string]string{"lodash": "4.17.21"},
	})
	writeFile(t, r2bJoin(root, "pnpm-lock.yaml"), `lockfileVersion: '9.0'
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
  lodash@4.17.20: {}
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusComponent || got.Complete {
		t.Fatalf("pnpm package without matching v9 snapshot became definitive: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedMetadata) && !hasCoverageKind(got.Coverage, jsresolution.CoverageMalformedMetadata) {
		t.Fatalf("missing pnpm snapshot lacks explicit fail-closed coverage: %#v", got.Coverage)
	}
}
