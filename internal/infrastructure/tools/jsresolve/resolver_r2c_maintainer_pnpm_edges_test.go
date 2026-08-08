package jsresolve

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestMaintainerAuditPNPMPeerSuffixedIdentityCorrelatesBasePURL(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "pnpm@10.15.0",
		"dependencies":   map[string]string{"react-dom": "19.2.0"},
	})
	writeFile(t, r2bJoin(root, "pnpm-lock.yaml"), `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react-dom:
        specifier: 19.2.0
        version: 19.2.0(react@19.2.0)
packages:
  react-dom@19.2.0:
    resolution: {integrity: sha512-valid}
snapshots:
  react-dom@19.2.0(react@19.2.0): {}
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "react-dom", Version: "19.2.0", PURL: "pkg:npm/react-dom@19.2.0"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "react-dom"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusComponent || got.Imports[0].Package.PURL != "pkg:npm/react-dom@19.2.0" || !got.Complete {
		t.Fatalf("pnpm peer-context instance did not preserve base npm package identity: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
}

func TestMaintainerAuditPNPMMultipleMainDocumentsFailClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "pnpm@11.0.0",
		"dependencies":   map[string]string{"lodash": "4.17.21"},
	})
	writeFile(t, r2bJoin(root, "pnpm-lock.yaml"), `---
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      lodash:
        specifier: 4.17.20
        version: 4.17.20
packages:
  lodash@4.17.20:
    resolution: {integrity: sha512-a}
snapshots:
  lodash@4.17.20: {}
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
    resolution: {integrity: sha512-b}
snapshots:
  lodash@4.17.21: {}
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusComponent || got.Complete {
		t.Fatalf("multiple pnpm main documents selected one arbitrarily: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageMalformedMetadata) && !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedMetadata) {
		t.Fatalf("multiple pnpm main documents lack explicit coverage: %#v", got.Coverage)
	}
}

func TestMaintainerAuditPNPMUnknownAuxiliaryDocumentFailsClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "pnpm@11.0.0",
		"dependencies":   map[string]string{"lodash": "4.17.21"},
	})
	writeFile(t, r2bJoin(root, "pnpm-lock.yaml"), `---
lockfileVersion: mystery-1.0
metadata:
  arbitrary: true
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
	if got.Imports[0].Status == jsresolution.StatusComponent || got.Complete {
		t.Fatalf("unknown pnpm auxiliary document was ignored while creating certainty: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedMetadata) {
		t.Fatalf("unknown pnpm auxiliary document lacks unsupported coverage: %#v", got.Coverage)
	}
}
