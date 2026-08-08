package jsresolve

import (
	"context"
	"fmt"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestResolverR2CPackageManagerSelectsMatchingLock(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":           "root",
		"packageManager": "npm@11.0.0",
		"dependencies":   map[string]string{"lodash": "4.17.21"},
	})
	writeJSON(t, r2bJoin(root, "package-lock.json"), map[string]any{
		"lockfileVersion": 3,
		"packages": map[string]any{
			"":                    map[string]any{"dependencies": map[string]string{"lodash": "4.17.21"}},
			"node_modules/lodash": map[string]any{"version": "4.17.21"},
		},
	})
	// A stale lock from another manager must not override an explicit
	// packageManager declaration selecting npm for this package scope.
	writeFile(t, r2bJoin(root, "yarn.lock"), `"lodash@3.10.1":
  version "3.10.1"
`)
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "lodash", Version: "3.10.1", PURL: "pkg:npm/lodash@3.10.1"},
		{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"},
	}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusComponent || got.Imports[0].Package.PURL != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("explicit npm packageManager did not select npm lock evidence: %#v coverage=%#v", got.Imports[0], got.Coverage)
	}
}

func TestResolverR2CTruncatedLockDiscoveryCannotProduceDefinitiveComponent(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	for i := 0; i < 8; i++ {
		writeJSON(t, r2bJoin(root, fmt.Sprintf("nested-%02d", i), "package.json"), map[string]any{"name": fmt.Sprintf("nested-%02d", i)})
	}
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}
	limits := defaultResolverLimits()
	limits.maxLockEntries = 3
	resolver := newResolverWithLimits(NewInventoryBuilder(), newAliasInventoryBuilder(), limits)

	got, err := resolver.Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusComponent {
		t.Fatalf("truncated lock discovery produced a definitive component: %#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if got.Complete {
		t.Fatalf("truncated lock discovery reported complete: %#v", got)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageMetadataBudgetExceeded) {
		t.Fatalf("truncated discovery has no budget coverage: %#v", got.Coverage)
	}
}
