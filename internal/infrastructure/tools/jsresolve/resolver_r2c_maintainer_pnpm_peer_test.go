package jsresolve

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestMaintainerAuditPNPMScopedPeerSuffixedIdentityCorrelatesBasePURL(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "pnpm@10.15.0",
		"dependencies":   map[string]string{"@scope/pkg": "1.2.3"},
	})
	writeFile(t, r2bJoin(root, "pnpm-lock.yaml"), `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      '@scope/pkg':
        specifier: 1.2.3
        version: 1.2.3(react@19.2.0)
packages:
  '@scope/pkg@1.2.3':
    resolution: {integrity: sha512-valid}
snapshots:
  '@scope/pkg@1.2.3(react@19.2.0)': {}
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "@scope/pkg", Version: "1.2.3", PURL: "pkg:npm/%40scope/pkg@1.2.3"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "@scope/pkg/subpath"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusComponent || got.Imports[0].Package.PURL != "pkg:npm/%40scope/pkg@1.2.3" || !got.Complete {
		t.Fatalf("scoped pnpm peer-context instance did not preserve base npm identity: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
}

func TestMaintainerAuditPNPMMalformedPeerSnapshotSuffixFailsClosed(t *testing.T) {
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
  'react-dom@19.2.0(react@19.2.0': {}
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "react-dom", Version: "19.2.0", PURL: "pkg:npm/react-dom@19.2.0"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "react-dom"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusComponent || got.Complete {
		t.Fatalf("malformed pnpm peer snapshot suffix became definitive: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedMetadata) && !hasCoverageKind(got.Coverage, jsresolution.CoverageMalformedMetadata) {
		t.Fatalf("malformed pnpm peer snapshot suffix lacks explicit coverage: %#v", got.Coverage)
	}
}

func TestMaintainerAuditPNPMPeerSuffixCannotChangeBaseVersion(t *testing.T) {
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
  react-dom@19.2.1:
    resolution: {integrity: sha512-wrong}
snapshots:
  react-dom@19.2.1(react@19.2.0): {}
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "react-dom", Version: "19.2.0", PURL: "pkg:npm/react-dom@19.2.0"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "react-dom"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusComponent || got.Complete {
		t.Fatalf("peer context washed out pnpm base-version disagreement: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
}
