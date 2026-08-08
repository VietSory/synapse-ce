package jsresolve

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestResolverR2CNonRegistryManifestRequestNeedsLockEvidence(t *testing.T) {
	t.Parallel()
	for _, request := range []string{"file:../lodash", "workspace:^", "link:../lodash", "github:org/repo", "../lodash"} {
		request := request
		t.Run(request, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
				"name": "root", "dependencies": map[string]string{"lodash": request},
			})
			doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}
			got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
			if err != nil {
				t.Fatal(err)
			}
			if got.Imports[0].Status == jsresolution.StatusComponent || got.Complete {
				t.Fatalf("manifest request %q became a definitive npm component without safe lock evidence: %#v coverage=%#v", request, got.Imports[0], got.Coverage)
			}
		})
	}
}

func TestResolverR2CExternalLockCannotEraseIdentityChangingManifestProtocol(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name": "root", "packageManager": "npm@11.6.0", "dependencies": map[string]string{"lodash": "file:../lodash"},
	})
	writeNPMResolvedLock(t, r2bJoin(root, "package-lock.json"), "lodash", "4.17.21")
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusComponent || got.Complete {
		t.Fatalf("stale/inconsistent external lock erased file: manifest evidence: %#v coverage=%#v", got.Imports[0], got.Coverage)
	}
}

func TestResolverR2CUnsupportedPackageManagerWithoutLockFailsClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name": "root", "packageManager": "bun@1.3.0", "dependencies": map[string]string{"lodash": "^4"},
	})
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusComponent || got.Complete {
		t.Fatalf("unsupported package manager produced definitive component: %#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedPackageManager) {
		t.Fatalf("unsupported package manager lacks explicit coverage: %#v", got.Coverage)
	}
}
