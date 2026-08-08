package jsresolve

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.JSImportResolver = (*Resolver)(nil)

// Resolve implements source-only JS/TS package identity resolution through R2C:
// lexical/alias resolution, importer lockfile context, and exact npm SBOM PURL
// correlation. It remains offline and makes no reachability judgment.
func (r *Resolver) Resolve(ctx context.Context, root string, graph modulegraph.Graph, doc *sbom.SBOM) (jsresolution.Result, error) {
	if ctx == nil {
		return jsresolution.Result{}, fmt.Errorf("%w: context is required", shared.ErrValidation)
	}
	if r == nil || r.inventory == nil || r.aliases == nil {
		return jsresolution.Result{}, fmt.Errorf("%w: resolver is not initialized", shared.ErrValidation)
	}
	if err := r.limits.validate(); err != nil {
		return jsresolution.Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return jsresolution.Result{}, err
	}
	if len(graph.Modules) == 0 {
		return jsresolution.Result{}, fmt.Errorf("%w: module graph has no modules", shared.ErrValidation)
	}
	if len(graph.Modules) > r.limits.maxModules || len(graph.Edges) > r.limits.maxEdges || len(graph.Coverage) > r.limits.maxGraphCoverage {
		return jsresolution.Result{}, fmt.Errorf("%w: module graph exceeds resolver budget", shared.ErrValidation)
	}
	for _, module := range graph.Modules {
		if len(module.Path) > r.limits.maxModulePathBytes || repositorySegmentCount(module.Path) > r.limits.maxModulePathSegments {
			return jsresolution.Result{}, fmt.Errorf("%w: module graph path exceeds resolver budget", shared.ErrValidation)
		}
	}
	totalBindings := 0
	for _, edge := range graph.Edges {
		if edge.Specifier == "" || strings.IndexByte(edge.Specifier, 0) >= 0 ||
			len(edge.From) > r.limits.maxModulePathBytes || len(edge.To) > r.limits.maxModulePathBytes ||
			repositorySegmentCount(edge.From) > r.limits.maxModulePathSegments || repositorySegmentCount(edge.To) > r.limits.maxModulePathSegments ||
			len(edge.Bindings) > r.limits.maxBindingsPerEdge || len(edge.Specifier) > r.limits.maxSpecifierBytes {
			return jsresolution.Result{}, fmt.Errorf("%w: module graph edge exceeds resolver budget", shared.ErrValidation)
		}
		if len(edge.Bindings) > r.limits.maxTotalBindings-totalBindings {
			return jsresolution.Result{}, fmt.Errorf("%w: module graph binding work exceeds resolver budget", shared.ErrValidation)
		}
		totalBindings += len(edge.Bindings)
	}
	normalizedGraph, err := modulegraph.Normalize(graph)
	if err != nil {
		return jsresolution.Result{}, fmt.Errorf("%w: invalid module graph: %v", shared.ErrValidation, err)
	}
	for _, edge := range normalizedGraph.Edges {
		classified := jsresolution.ClassifySpecifier(edge.Specifier)
		if edge.To != "" && classified.Kind != jsresolution.SpecifierRelative {
			return jsresolution.Result{}, fmt.Errorf("%w: resolved graph edge %q -> %q has non-relative specifier %q", shared.ErrValidation, edge.From, edge.To, edge.Specifier)
		}
	}

	inventory, err := r.inventory.Build(ctx, root)
	if err != nil {
		return jsresolution.Result{}, err
	}
	aliases, err := r.aliases.Build(ctx, root)
	if err != nil {
		return jsresolution.Result{}, err
	}
	if !aliases.scopeDiscoveryComplete {
		aliases.packageScopes = makePackageScopesGloballyUncertain(aliases.packageScopes)
	}
	components, err := buildNPMComponentIndex(ctx, doc, r.limits)
	if err != nil {
		return jsresolution.Result{}, err
	}
	locks, err := buildCompleteLockContext(ctx, root, inventory.Packages, r.limits)
	if err != nil {
		return jsresolution.Result{}, err
	}

	coverage := resolutionCoverageSink{limit: r.limits.maxCoverageIssues}
	aliasWork := resolverWorkBudget{remaining: r.limits.maxAliasWork}
	candidateWork := resolverWorkBudget{remaining: r.limits.maxCandidateWork}
	lockWork := resolverWorkBudget{remaining: r.limits.maxLockWork}
	coverage.addAll(inventory.Coverage)
	coverage.addAll(aliases.coverage)
	coverage.addAll(components.coverage)
	coverage.addAll(locks.coverage)

	moduleByPath := make(map[string]modulegraph.Module, len(normalizedGraph.Modules))
	modulePaths := make(map[string]struct{}, len(normalizedGraph.Modules))
	for _, module := range normalizedGraph.Modules {
		moduleByPath[module.Path] = module
		modulePaths[module.Path] = struct{}{}
	}
	workspaceByName := indexWorkspacesByName(inventory.Packages)

	result := jsresolution.Result{GraphCoverage: append([]modulegraph.CoverageIssue(nil), normalizedGraph.Coverage...)}
	for _, edge := range normalizedGraph.Edges {
		if err := ctx.Err(); err != nil {
			return jsresolution.Result{}, err
		}
		if edge.To != "" {
			continue
		}
		classified := jsresolution.ClassifySpecifier(edge.Specifier)
		if classified.Kind == jsresolution.SpecifierRelative {
			if !relativeEdgeHasCoverage(normalizedGraph.Coverage, edge) {
				return jsresolution.Result{}, fmt.Errorf("%w: unresolved relative edge from %q has no graph coverage", shared.ErrValidation, edge.From)
			}
			continue
		}
		resolution := jsresolution.ImportResolution{
			From:      edge.From,
			Specifier: edge.Specifier,
			Position:  edge.Position,
			Kind:      edge.Kind,
			TypeOnly:  edge.TypeOnly,
		}
		if module, ok := moduleByPath[edge.From]; ok {
			resolution.DeclarationOnly = module.DeclarationOnly
		}
		edgeCoverage := resolutionCoverageSink{limit: r.limits.maxCoverageIssues}

		switch classified.Kind {
		case jsresolution.SpecifierBuiltin:
			resolution.Status = jsresolution.StatusBuiltin
			resolution.Package = jsresolution.PackageIdentity{Name: classified.BuiltinName}
		case jsresolution.SpecifierPackageImport:
			resolution = r.resolvePackageImport(ctx, resolution, aliases.mappings, aliases.packageScopes, aliases.scopeDiscoveryComplete, workspaceByName, inventory.Packages, &aliasWork, &candidateWork, &edgeCoverage)
		case jsresolution.SpecifierPackage:
			if aliasResolution, handled := r.resolveTSPaths(ctx, resolution, aliases.mappings, aliases.configs, aliases.scopeDiscoveryComplete, workspaceByName, inventory.Packages, modulePaths, &aliasWork, &candidateWork, &edgeCoverage); handled {
				resolution = aliasResolution
			} else if self, ok := packageForRepositoryTarget(inventory.Packages, resolution.From); ok && self.Name == classified.PackageName {
				resolution.Status = jsresolution.StatusUnresolved
				resolution.Package = jsresolution.PackageIdentity{Name: classified.PackageName}
				resolution.Reason = "same-package self-reference requires package.json exports semantics that R2C does not resolve"
				edgeCoverage.add(jsresolution.CoverageIssue{
					Kind: jsresolution.CoverageUnresolvedSpecifier, Path: resolution.From,
					Detail: fmt.Sprintf("specifier %q may be a package self-reference", resolution.Specifier),
				})
			} else {
				resolution = r.resolvePackageRoot(resolution, classified.PackageName, workspaceByName, &candidateWork, &edgeCoverage)
			}
		default:
			if aliasResolution, handled := r.resolveTSPaths(ctx, resolution, aliases.mappings, aliases.configs, aliases.scopeDiscoveryComplete, workspaceByName, inventory.Packages, modulePaths, &aliasWork, &candidateWork, &edgeCoverage); handled {
				resolution = aliasResolution
			} else {
				resolution.Status = jsresolution.StatusUnsupported
				resolution.Reason = "unsupported module specifier form"
				edgeCoverage.add(jsresolution.CoverageIssue{
					Kind: jsresolution.CoverageUnsupportedSpecifier, Path: edge.From,
					Detail: fmt.Sprintf("specifier %q is outside the supported source-only R2C forms", edge.Specifier),
				})
			}
		}
		if err := ctx.Err(); err != nil {
			return jsresolution.Result{}, err
		}
		beforeCorrelation := resolution.Status
		resolution = r.correlateFinalResolution(ctx, resolution, inventory.Packages, aliases.packageScopes, workspaceByName, components, locks, &lockWork, &candidateWork, &edgeCoverage)
		if err := ctx.Err(); err != nil {
			return jsresolution.Result{}, err
		}
		addFinalEdgeCoverage(&coverage, edgeCoverage.issues, beforeCorrelation, resolution.Status)
		result.Imports = append(result.Imports, resolution)
	}
	result.Coverage = coverage.issues
	return jsresolution.NormalizeResult(result)
}
