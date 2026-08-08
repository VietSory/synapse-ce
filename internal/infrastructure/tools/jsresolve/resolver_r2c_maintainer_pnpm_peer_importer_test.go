package jsresolve

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestMaintainerAuditPNPMMalformedImporterPeerSuffixFailsClosed(t *testing.T) {
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
        version: '19.2.0('
packages:
  react-dom@19.2.0:
    resolution: {integrity: sha512-valid}
snapshots:
  react-dom@19.2.0: {}
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "react-dom", Version: "19.2.0", PURL: "pkg:npm/react-dom@19.2.0"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "react-dom"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusComponent || got.Complete {
		t.Fatalf("malformed pnpm importer peer suffix became definitive: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedMetadata) && !hasCoverageKind(got.Coverage, jsresolution.CoverageMalformedMetadata) {
		t.Fatalf("malformed pnpm importer peer suffix lacks explicit coverage: %#v", got.Coverage)
	}
}
