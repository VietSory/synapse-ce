package jsresolve

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestResolverR2CIncompletePackageScopeDiscoveryCannotProduceDefinitiveComponent(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	writeFile(t, r2bJoin(root, "src", "index.ts"), `import "lodash"`)
	writeJSON(t, r2bJoin(root, "z-nearer", "package.json"), map[string]any{"name": "nearer"})

	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}
	aliasLimits := defaultAliasLimits()
	aliasLimits.maxEntries = 2
	resolver := newResolverWithLimits(NewInventoryBuilder(), newAliasInventoryBuilderWithLimits(aliasLimits), defaultResolverLimits())

	got, err := resolver.Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusComponent {
		t.Fatalf("incomplete package-scope discovery produced definitive component: %#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if got.Complete {
		t.Fatalf("incomplete package-scope discovery reported complete: %#v", got)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageMetadataBudgetExceeded) {
		t.Fatalf("incomplete package-scope discovery has no budget coverage: %#v", got.Coverage)
	}
}

func TestSelectionsForPackageTreatsUncertainBoundaryAsUnsafeWithoutLock(t *testing.T) {
	t.Parallel()
	ctx := lockContext{bindings: map[string][]lockSelection{}}
	selections, found, uncertain, exhausted := ctx.selectionsForPackage(
		"packages/app/src/index.ts",
		"lodash",
		[]aliasPackageContext{{source: "packages/app/package.json", scopeDir: "packages/app", uncertain: true}},
		&resolverWorkBudget{remaining: 10},
	)
	if exhausted || !found || !uncertain || len(selections) != 0 {
		t.Fatalf("uncertain package boundary was not fail-closed: selections=%#v found=%v uncertain=%v exhausted=%v", selections, found, uncertain, exhausted)
	}
}
