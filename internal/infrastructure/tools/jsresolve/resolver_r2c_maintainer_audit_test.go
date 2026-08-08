package jsresolve

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestMaintainerAuditYarnResolutionIdentityMismatchFailsClosed(t *testing.T) {
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
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{
		Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21",
	}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusComponent || got.Complete {
		t.Fatalf("inconsistent Yarn resolution identity became definitive: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedMetadata) && !hasCoverageKind(got.Coverage, jsresolution.CoverageMalformedMetadata) {
		t.Fatalf("inconsistent Yarn resolution identity lacks explicit fail-closed coverage: %#v", got.Coverage)
	}
}

func TestMaintainerAuditYarnNPMProtocolExactVersionCorrelates(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "yarn@4.9.0",
		"dependencies":   map[string]string{"lodash": "npm:4.17.21"},
	})
	writeFile(t, r2bJoin(root, "yarn.lock"), `__metadata:
  version: 8

"lodash@npm:4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{
		Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21",
	}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusComponent || got.Imports[0].Package.PURL != "pkg:npm/lodash@4.17.21" || !got.Complete {
		t.Fatalf("valid Yarn npm: exact-version protocol was not correlated: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
}

func TestMaintainerAuditYarnNPMProtocolWithoutDeclaredManagerFailsClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":         "root",
		"dependencies": map[string]string{"lodash": "npm:4.17.21"},
	})
	writeFile(t, r2bJoin(root, "yarn.lock"), `__metadata:
  version: 8

"lodash@npm:4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{
		Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21",
	}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusComponent || got.Complete {
		t.Fatalf("npm: exact version was trusted without a declared Yarn manager: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
}

func TestMaintainerAuditYarnNPMResolutionWithArchiveLocatorParamsCorrelates(t *testing.T) {
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
  resolution: "lodash@npm:4.17.21::__archiveUrl=https%3A%2F%2Fregistry.example%2Flodash.tgz"
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{
		Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21",
	}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusComponent || !got.Complete {
		t.Fatalf("valid Yarn npm locator params were rejected: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
}
