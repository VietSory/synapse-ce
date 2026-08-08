package jsresolve

import (
	"context"
	"fmt"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestMaintainerAuditYarnSupportedLockVersionsCorrelate(t *testing.T) {
	t.Parallel()
	for _, lockVersion := range []int{8, 10} {
		lockVersion := lockVersion
		t.Run(fmt.Sprintf("v%d", lockVersion), func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
				"name":           "root",
				"packageManager": "yarn@4.9.0",
				"dependencies":   map[string]string{"lodash": "4.17.21"},
			})
			writeFile(t, r2bJoin(root, "yarn.lock"), fmt.Sprintf(`__metadata:
  version: %d

"lodash@npm:4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
`, lockVersion))
			doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}

			got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
			if err != nil {
				t.Fatal(err)
			}
			if got.Imports[0].Status != jsresolution.StatusComponent || got.Imports[0].Package.PURL != "pkg:npm/lodash@4.17.21" || !got.Complete {
				t.Fatalf("supported Yarn lock version %d was not correlated: import=%#v coverage=%#v", lockVersion, got.Imports[0], got.Coverage)
			}
		})
	}
}

func TestMaintainerAuditYarnUnknownLockVersionFailsClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "yarn@99.0.0",
		"dependencies":   map[string]string{"lodash": "4.17.21"},
	})
	writeFile(t, r2bJoin(root, "yarn.lock"), `__metadata:
  version: 99

"lodash@npm:4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusComponent || got.Complete {
		t.Fatalf("unknown Yarn lockfile version became definitive: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedMetadata) {
		t.Fatalf("unknown Yarn lockfile version lacks unsupported-metadata coverage: %#v", got.Coverage)
	}
}
