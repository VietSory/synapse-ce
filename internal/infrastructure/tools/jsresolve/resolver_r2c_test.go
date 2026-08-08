package jsresolve

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestResolverR2CCorrelatesExactSBOMPURLAndPreservesEdgeSemantics(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{{Path: "types/api.d.ts", Dialect: modulegraph.DialectTypeScript, DeclarationOnly: true}},
		Edges: []modulegraph.Edge{{
			From: "types/api.d.ts", Specifier: "@scope/pkg/subpath", Kind: modulegraph.ImportESMStatic,
			TypeOnly: true, Position: modulegraph.Position{Line: 4, Column: 2},
		}},
	}
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "@scope/pkg", Version: "1.2.3", PURL: "pkg:npm/%40scope/pkg@1.2.3"}}}
	got, err := NewResolver().Resolve(context.Background(), root, graph, doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Imports) != 1 {
		t.Fatalf("imports = %#v", got.Imports)
	}
	resolution := got.Imports[0]
	if resolution.Status != jsresolution.StatusComponent || resolution.Package.PURL != "pkg:npm/%40scope/pkg@1.2.3" || resolution.Package.Name != "@scope/pkg" || resolution.Package.Version != "1.2.3" {
		t.Fatalf("component resolution = %#v", resolution)
	}
	if !resolution.TypeOnly || !resolution.DeclarationOnly || resolution.Kind != modulegraph.ImportESMStatic || resolution.Position.Line != 4 {
		t.Fatalf("edge semantics were not preserved: %#v", resolution)
	}
	if !got.Complete || len(got.Coverage) != 0 {
		t.Fatalf("unique exact component correlation should be complete: %#v", got)
	}
}

func TestResolverR2CPreservesAllSBOMCandidatesInsteadOfPickingFirst(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"},
		{Name: "lodash", Version: "3.10.1", PURL: "pkg:npm/lodash@3.10.1"},
	}}
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash/fp"), doc)
	if err != nil {
		t.Fatal(err)
	}
	resolution := got.Imports[0]
	if resolution.Status != jsresolution.StatusAmbiguous || len(resolution.Candidates) != 2 {
		t.Fatalf("multiple SBOM versions were not preserved: %#v", resolution)
	}
	if resolution.Candidates[0].Version != "3.10.1" || resolution.Candidates[1].Version != "4.17.21" {
		t.Fatalf("candidates are not deterministic: %#v", resolution.Candidates)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageAmbiguousSBOMComponent) || got.Complete {
		t.Fatalf("SBOM ambiguity did not make coverage incomplete: %#v", got)
	}
}

func TestResolverR2CPackageLockSelectsImporterVersion(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root", "packageManager": "npm@10.8.2"})
	writeJSON(t, r2bJoin(root, "package-lock.json"), map[string]any{
		"lockfileVersion": 3,
		"packages": map[string]any{
			"":                    map[string]any{"dependencies": map[string]string{"lodash": "^4.17.0"}},
			"node_modules/lodash": map[string]any{"version": "4.17.21"},
		},
	})
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "lodash", Version: "3.10.1", PURL: "pkg:npm/lodash@3.10.1"},
		{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"},
	}}
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusComponent || got.Imports[0].Package.PURL != "pkg:npm/lodash@4.17.21" || !got.Complete {
		t.Fatalf("package-lock importer selection = %#v", got)
	}
}

func TestResolverR2CPackageLockLinkSelectsWorkspace(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root", "packageManager": "npm@10.8.2", "workspaces": []string{"packages/*"}})
	writeJSON(t, r2bJoin(root, "packages", "app", "package.json"), map[string]any{"name": "app"})
	writeJSON(t, r2bJoin(root, "packages", "shared", "package.json"), map[string]any{"name": "shared", "version": "1.0.0"})
	writeJSON(t, r2bJoin(root, "package-lock.json"), map[string]any{
		"lockfileVersion": 3,
		"packages": map[string]any{
			"":                    map[string]any{},
			"packages/app":        map[string]any{"dependencies": map[string]string{"shared": "*"}},
			"packages/shared":     map[string]any{"name": "shared", "version": "1.0.0"},
			"node_modules/shared": map[string]any{"resolved": "packages/shared", "link": true},
		},
	})
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "shared", Version: "9.0.0", PURL: "pkg:npm/shared@9.0.0"}}}
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("packages/app/src/index.ts", "shared"), doc)
	if err != nil {
		t.Fatal(err)
	}
	resolution := got.Imports[0]
	if resolution.Status != jsresolution.StatusWorkspace || resolution.Package.Path != "packages/shared" || !resolution.Package.Workspace {
		t.Fatalf("npm workspace link was not selected: %#v coverage=%#v", resolution, got.Coverage)
	}
	if hasCoverageKind(got.Coverage, jsresolution.CoverageUnresolvedSpecifier) || hasCoverageKind(got.Coverage, jsresolution.CoverageAmbiguousSBOMComponent) {
		t.Fatalf("resolved R2B provisional ambiguity leaked into final coverage: %#v", got.Coverage)
	}
}

func TestResolverR2CLockSelectedVersionMustExistInSBOM(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root", "packageManager": "npm@10"})
	writeJSON(t, r2bJoin(root, "package-lock.json"), map[string]any{"lockfileVersion": 3, "packages": map[string]any{
		"":                    map[string]any{"dependencies": map[string]string{"lodash": "^4"}},
		"node_modules/lodash": map[string]any{"version": "4.17.21"},
	}})
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "3.10.1", PURL: "pkg:npm/lodash@3.10.1"}}}
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusUnresolved || got.Imports[0].Package.PURL != "" || !hasCoverageKind(got.Coverage, jsresolution.CoverageMissingSBOMComponent) {
		t.Fatalf("missing lock-selected SBOM component produced a phantom identity: %#v", got)
	}
}

func TestResolverR2CPNPMImporterDisambiguatesWorkspaceFromRegistry(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root", "packageManager": "pnpm@9", "workspaces": []string{"packages/*"}})
	writeJSON(t, r2bJoin(root, "packages", "app", "package.json"), map[string]any{"name": "app"})
	writeJSON(t, r2bJoin(root, "packages", "shared", "package.json"), map[string]any{"name": "shared", "version": "1.0.0"})
	writeFile(t, r2bJoin(root, "pnpm-lock.yaml"), `lockfileVersion: '9.0'
importers:
  packages/app:
    dependencies:
      shared:
        specifier: 2.0.0
        version: 2.0.0
packages:
  shared@2.0.0:
    resolution: {integrity: sha512-valid}
snapshots:
  shared@2.0.0: {}
`)
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "shared", Version: "1.0.0", PURL: "pkg:npm/shared@1.0.0"},
		{Name: "shared", Version: "2.0.0", PURL: "pkg:npm/shared@2.0.0"},
	}}
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("packages/app/src/index.ts", "shared"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusComponent || got.Imports[0].Package.PURL != "pkg:npm/shared@2.0.0" {
		t.Fatalf("pnpm importer did not select registry component: %#v coverage=%#v", got.Imports[0], got.Coverage)
	}
}

func TestResolverR2CPNPMLinkSelectsObservedWorkspace(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root", "packageManager": "pnpm@9", "workspaces": []string{"packages/*"}})
	writeJSON(t, r2bJoin(root, "packages", "app", "package.json"), map[string]any{"name": "app"})
	writeJSON(t, r2bJoin(root, "packages", "shared", "package.json"), map[string]any{"name": "shared", "version": "1.0.0"})
	writeFile(t, r2bJoin(root, "pnpm-lock.yaml"), `lockfileVersion: '9.0'
importers:
  packages/app:
    dependencies:
      shared:
        specifier: workspace:*
        version: link:../shared
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "shared", Version: "2.0.0", PURL: "pkg:npm/shared@2.0.0"}}}
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("packages/app/src/index.ts", "shared"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusWorkspace || got.Imports[0].Package.Path != "packages/shared" {
		t.Fatalf("pnpm workspace link correlation = %#v coverage=%#v", got.Imports[0], got.Coverage)
	}
}

func TestResolverR2CYarnDescriptorSelectsExactExternalVersion(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root", "packageManager": "yarn@1.22.22", "dependencies": map[string]string{"lodash": "4.17.21"}})
	writeFile(t, r2bJoin(root, "yarn.lock"), `lodash@4.17.21:
  version "4.17.21"
`)
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "lodash", Version: "4.17.20", PURL: "pkg:npm/lodash@4.17.20"},
		{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"},
	}}
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusComponent || got.Imports[0].Package.Version != "4.17.21" {
		t.Fatalf("Yarn descriptor correlation = %#v", got.Imports[0])
	}
}

func TestResolverR2CYarnWorkspaceProtocolDoesNotSelectRegistryTwin(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root", "packageManager": "yarn@4", "workspaces": []string{"packages/*"}})
	writeJSON(t, r2bJoin(root, "packages", "app", "package.json"), map[string]any{"name": "app", "dependencies": map[string]string{"shared": "workspace:*"}})
	writeJSON(t, r2bJoin(root, "packages", "shared", "package.json"), map[string]any{"name": "shared", "version": "1.0.0"})
	writeFile(t, r2bJoin(root, "yarn.lock"), `__metadata:
  version: 8
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "shared", Version: "1.0.0", PURL: "pkg:npm/shared@1.0.0"}}}
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("packages/app/src/index.ts", "shared"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusWorkspace || got.Imports[0].Package.Path != "packages/shared" {
		t.Fatalf("Yarn workspace protocol selected registry twin: %#v coverage=%#v", got.Imports[0], got.Coverage)
	}
}

func TestResolverR2CYarnBroadRangeWithWorkspaceStaysAmbiguous(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root", "packageManager": "yarn@1.22.22", "workspaces": []string{"packages/*"}})
	writeJSON(t, r2bJoin(root, "packages", "app", "package.json"), map[string]any{"name": "app", "dependencies": map[string]string{"shared": "^1.0.0"}})
	writeJSON(t, r2bJoin(root, "packages", "shared", "package.json"), map[string]any{"name": "shared", "version": "1.0.0"})
	writeFile(t, r2bJoin(root, "yarn.lock"), `shared@^1.0.0:
  version "1.5.0"
`)
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "shared", Version: "1.5.0", PURL: "pkg:npm/shared@1.5.0"}}}
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("packages/app/src/index.ts", "shared"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusAmbiguous || !hasWorkspaceCandidate(got.Imports[0].Candidates, "shared", "packages/shared") {
		t.Fatalf("broad Yarn range guessed registry/workspace identity: %#v", got.Imports[0])
	}
}

func TestResolverR2CPackageImportExternalTargetGetsComponent(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root", "imports": map[string]any{"#dep": "lodash/fp"}})
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "#dep"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusComponent || got.Imports[0].Package.PURL != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("package imports target not correlated: %#v coverage=%#v", got.Imports[0], got.Coverage)
	}
}

func TestResolverR2CSelfReferenceRemainsUnresolvedEvenWithMatchingSBOM(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "my-app"})
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "my-app", Version: "9.9.9", PURL: "pkg:npm/my-app@9.9.9"}}}
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "my-app/subpath"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusUnresolved || got.Imports[0].Package.PURL != "" || !hasCoverageKind(got.Coverage, jsresolution.CoverageUnresolvedSpecifier) {
		t.Fatalf("self-reference was miscorrelated to third-party SBOM component: %#v", got)
	}
}

func TestResolverR2CMalformedNpmPURLCannotBecomeComponent(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "@scope/pkg", Version: "1.2.3", PURL: "pkg:npm/@scope/pkg@1.2.3"}}}
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "@scope/pkg"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusUnresolved || !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedMetadata) || !hasCoverageKind(got.Coverage, jsresolution.CoverageMissingSBOMComponent) {
		t.Fatalf("non-canonical scoped npm PURL was trusted: %#v", got)
	}
}

func TestResolverR2CMultipleManagersAtSameScopeFailClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root", "dependencies": map[string]string{"lodash": "2.0.0"}})
	writeJSON(t, r2bJoin(root, "package-lock.json"), map[string]any{"lockfileVersion": 3, "packages": map[string]any{
		"":                    map[string]any{"dependencies": map[string]string{"lodash": "1.0.0"}},
		"node_modules/lodash": map[string]any{"version": "1.0.0"},
	}})
	writeFile(t, r2bJoin(root, "yarn.lock"), `lodash@2.0.0:
  version "2.0.0"
`)
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "lodash", Version: "1.0.0", PURL: "pkg:npm/lodash@1.0.0"},
		{Name: "lodash", Version: "2.0.0", PURL: "pkg:npm/lodash@2.0.0"},
	}}
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusAmbiguous || !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedPackageManager) {
		t.Fatalf("multiple same-scope package managers produced false confidence: %#v", got)
	}
}

func TestResolverR2CSBOMAndLockBudgetsAreInjectable(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	limits := defaultResolverLimits()
	limits.maxSBOMComponents = 1
	resolver := newResolverWithLimits(NewInventoryBuilder(), newAliasInventoryBuilder(), limits)
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "a", Version: "1.0.0", PURL: "pkg:npm/a@1.0.0"},
		{Name: "b", Version: "1.0.0", PURL: "pkg:npm/b@1.0.0"},
	}}
	if _, err := resolver.Resolve(context.Background(), root, graphWithExternal("src/index.ts", "a"), doc); err == nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("SBOM component budget error = %v", err)
	}

	limits = defaultResolverLimits()
	limits.maxLockWork = 1
	resolver = newResolverWithLimits(NewInventoryBuilder(), newAliasInventoryBuilder(), limits)
	writeJSON(t, r2bJoin(root, "package-lock.json"), map[string]any{"lockfileVersion": 3, "packages": map[string]any{
		"":               map[string]any{"dependencies": map[string]string{"a": "1.0.0"}},
		"node_modules/a": map[string]any{"version": "1.0.0"},
	}})
	got, err := resolver.Resolve(context.Background(), root, graphWithExternal("deep/src/index.ts", "a"), &sbom.SBOM{Components: []sbom.Component{{Name: "a", Version: "1.0.0", PURL: "pkg:npm/a@1.0.0"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusUnresolved || !hasCoverageKind(got.Coverage, jsresolution.CoverageMetadataBudgetExceeded) {
		t.Fatalf("lock correlation work budget did not fail closed: %#v", got)
	}
}
