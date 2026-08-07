package jsresolve

import (
	"context"
	"fmt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"sort"
)

func indexWorkspacesByName(packages []jsresolution.PackageMetadata) map[string][]jsresolution.PackageIdentity {
	out := make(map[string][]jsresolution.PackageIdentity)
	for _, pkg := range packages {
		if !pkg.Workspace || pkg.Name == "" {
			continue
		}
		identity := packageMetadataIdentity(pkg)
		out[pkg.Name] = append(out[pkg.Name], identity)
	}
	for name := range out {
		sort.Slice(out[name], func(i, j int) bool { return identityLess(out[name][i], out[name][j]) })
		out[name] = deduplicatePackageIdentities(out[name])
	}
	return out
}

func (r *Resolver) resolvePackageRoot(base jsresolution.ImportResolution, packageName string, workspaces map[string][]jsresolution.PackageIdentity, coverage *resolutionCoverageSink) jsresolution.ImportResolution {
	candidates := workspaces[packageName]
	switch {
	case len(candidates) == 0:
		base.Status = jsresolution.StatusUnresolved
		base.Package = jsresolution.PackageIdentity{Name: packageName}
		base.Reason = "npm package root classified; SBOM component correlation deferred to R2C"
	case len(candidates) == 1:
		base.Status = jsresolution.StatusWorkspace
		base.Package = candidates[0]
	case len(candidates) > r.limits.maxCandidates:
		base.Status = jsresolution.StatusUnresolved
		base.Package = jsresolution.PackageIdentity{Name: packageName}
		base.Reason = "workspace identity candidate budget exceeded"
		coverage.add(jsresolution.CoverageIssue{
			Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: base.From,
			Detail: fmt.Sprintf("workspace candidate budget exceeded for %q (%d)", packageName, r.limits.maxCandidates),
		})
	default:
		base.Status = jsresolution.StatusAmbiguous
		base.Candidates = append([]jsresolution.PackageIdentity(nil), candidates...)
		base.Reason = "package name maps to multiple local workspace identities"
	}
	return base
}

func (r *Resolver) resolvePackageImport(
	ctx context.Context,
	base jsresolution.ImportResolution,
	mappings []aliasMapping,
	packageScopes []aliasPackageContext,
	scopeDiscoveryComplete bool,
	workspaces map[string][]jsresolution.PackageIdentity,
	packages []jsresolution.PackageMetadata,
	budget *resolverWorkBudget,
	coverage *resolutionCoverageSink,
) jsresolution.ImportResolution {
	if !scopeDiscoveryComplete {
		base.Status = jsresolution.StatusUnresolved
		base.Reason = "package scope discovery is incomplete, so a nearer package boundary may be unknown"
		coverage.add(jsresolution.CoverageIssue{
			Kind: jsresolution.CoverageUnsupportedAlias, Path: base.From,
			Detail: fmt.Sprintf("package import %q cannot be scoped safely because alias metadata discovery is incomplete", base.Specifier),
		})
		return base
	}
	scope, ok := packageContextForImporter(packageScopes, base.From)
	if !ok {
		base.Status = jsresolution.StatusUnresolved
		base.Reason = "importer is not contained by an observed package.json boundary"
		coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnresolvedAlias, Path: base.From, Detail: fmt.Sprintf("package import %q has no containing package scope", base.Specifier)})
		return base
	}
	if scope.uncertain {
		base.Status = jsresolution.StatusUnresolved
		base.Reason = "nearest package.json boundary has incomplete or unsupported imports metadata"
		coverage.add(jsresolution.CoverageIssue{
			Kind: jsresolution.CoverageUnsupportedAlias, Path: base.From,
			Detail: fmt.Sprintf("package import %q cannot be resolved safely in package scope %q", base.Specifier, scope.scopeDir),
		})
		return base
	}
	if !scope.importsPresent {
		base.Status = jsresolution.StatusUnresolved
		base.Reason = "nearest package scope does not declare package.json imports"
		coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnresolvedAlias, Path: base.From, Detail: fmt.Sprintf("package import %q is not declared in package scope %q", base.Specifier, scope.scopeDir)})
		return base
	}
	matches, exhausted := bestAliasMatchesInScope(ctx, mappings, aliasPackageImports, scope.scopeDir, base.Specifier, budget)
	if exhausted {
		return markAliasBudgetExceeded(base, budget, coverage, r.limits.maxAliasWork)
	}
	if len(matches) == 0 {
		base.Status = jsresolution.StatusUnresolved
		base.Reason = "no supported package.json imports mapping exists in the nearest package scope"
		coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnresolvedAlias, Path: base.From, Detail: fmt.Sprintf("package import %q could not be resolved in package scope %q", base.Specifier, scope.scopeDir)})
		return base
	}
	return r.resolveAliasMatches(ctx, base, matches, workspaces, packages, nil, budget, coverage)
}
