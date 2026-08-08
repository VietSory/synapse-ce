package jsresolve

import (
	"context"
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
)

func (r *Resolver) correlateFinalResolution(
	ctx context.Context,
	base jsresolution.ImportResolution,
	packages []jsresolution.PackageMetadata,
	packageScopes []aliasPackageContext,
	workspaces map[string][]jsresolution.PackageIdentity,
	components npmComponentIndex,
	locks lockContext,
	lockWork, candidateWork *resolverWorkBudget,
	coverage *resolutionCoverageSink,
) jsresolution.ImportResolution {
	if base.Status != jsresolution.StatusUnresolved && base.Status != jsresolution.StatusAmbiguous {
		return base
	}
	if isSamePackageSelfReference(base, packages) {
		return base
	}
	placeholders := externalPlaceholders(base)
	if len(placeholders) == 0 {
		return base
	}

	managed := make(map[string]struct{}, len(placeholders))
	for _, placeholder := range placeholders {
		managed[placeholder.Name] = struct{}{}
	}
	var candidates []jsresolution.PackageIdentity
	if base.Status == jsresolution.StatusAmbiguous {
		for _, candidate := range base.Candidates {
			if isExternalPlaceholder(candidate) {
				continue
			}
			if candidate.Workspace {
				if _, ok := managed[candidate.Name]; ok {
					continue
				}
			}
			candidates = append(candidates, candidate)
		}
	}

	unresolvedExternal := false
	for _, placeholder := range placeholders {
		if err := ctx.Err(); err != nil {
			return base
		}
		name := placeholder.Name
		selections, foundLock, uncertain, exhausted := locks.selectionsForPackage(base.From, name, packageScopes, lockWork)
		if exhausted {
			return r.markLockBudgetExceeded(base, lockWork, coverage)
		}
		if len(selections) > 0 && !uncertain {
			resolved, missing := r.identitiesForFinalLockSelections(ctx, base, name, selections, workspaces, components, candidateWork, coverage)
			if candidateWork != nil && candidateWork.exceeded {
				return markCandidateBudgetExceeded(base, candidateWork, coverage, r.limits.maxCandidateWork)
			}
			candidates = append(candidates, resolved...)
			if len(missing) > 0 {
				candidates = append(candidates, missing...)
				unresolvedExternal = true
			}
			if len(resolved) > 0 || len(missing) > 0 {
				continue
			}
		}

		if foundLock && uncertain {
			if !r.appendFallbackIdentities(base, name, placeholder, workspaces, components, candidateWork, &candidates, true) {
				return markCandidateBudgetExceeded(base, candidateWork, coverage, r.limits.maxCandidateWork)
			}
			unresolvedExternal = true
			continue
		}

		before := len(candidates)
		if !r.appendFallbackIdentities(base, name, placeholder, workspaces, components, candidateWork, &candidates, false) {
			return markCandidateBudgetExceeded(base, candidateWork, coverage, r.limits.maxCandidateWork)
		}
		if len(components.candidates(name)) == 0 {
			unresolvedExternal = true
			coverage.add(jsresolution.CoverageIssue{
				Kind: jsresolution.CoverageMissingSBOMComponent, Path: base.From,
				Detail: fmt.Sprintf("npm package %q has no correlatable component PURL in the supplied SBOM", name),
			})
		}
		if len(candidates) == before {
			candidates = append(candidates, placeholder)
			unresolvedExternal = true
		}
	}

	if len(candidates) > r.limits.maxCandidates {
		base.Status = jsresolution.StatusUnresolved
		base.Package = jsresolution.PackageIdentity{}
		base.Candidates = nil
		base.Reason = "R2C correlation candidate budget exceeded"
		coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: base.From, Detail: fmt.Sprintf("R2C candidate budget exceeded for %q (%d)", base.Specifier, r.limits.maxCandidates)})
		return base
	}
	sort.Slice(candidates, func(i, j int) bool { return identityLess(candidates[i], candidates[j]) })
	candidates = deduplicatePackageIdentities(candidates)
	if len(candidates) == 0 {
		return base
	}
	if len(candidates) == 1 {
		candidate := candidates[0]
		switch {
		case isExternalUnmaterialized(candidate):
			base.Status = jsresolution.StatusUnresolved
			base.Package = jsresolution.PackageIdentity{Name: candidate.Name}
			base.Candidates = nil
			if candidate.Version == "" {
				base.Reason = "npm package identity has no exact SBOM component PURL"
			} else {
				base.Reason = fmt.Sprintf("lockfile selects npm package %s@%s but the supplied SBOM has no exact component PURL", candidate.Name, candidate.Version)
			}
		case candidate.Workspace:
			base.Status, base.Package, base.Candidates = jsresolution.StatusWorkspace, candidate, nil
			base.Reason = "importer lockfile context selects the local workspace"
		case candidate.PURL != "":
			base.Status, base.Package, base.Candidates = jsresolution.StatusComponent, candidate, nil
			base.Reason = "correlated to the exact npm component PURL in the supplied SBOM"
		case candidate.Path != "":
			base.Status, base.Package, base.Candidates = jsresolution.StatusLocal, candidate, nil
			base.Reason = "resolved to first-party source"
		}
		return base
	}

	base.Status = jsresolution.StatusAmbiguous
	base.Package = jsresolution.PackageIdentity{}
	base.Candidates = candidates
	if unresolvedExternal {
		base.Reason = "workspace or package identity remains viable because lock/SBOM evidence is incomplete"
	} else {
		base.Reason = "multiple workspace/SBOM package identities remain viable after importer correlation"
	}
	coverage.add(jsresolution.CoverageIssue{
		Kind: jsresolution.CoverageAmbiguousSBOMComponent, Path: base.From,
		Detail: fmt.Sprintf("specifier %q has %d viable package identities after R2C correlation", base.Specifier, len(candidates)),
	})
	return base
}

func (r *Resolver) appendFallbackIdentities(
	base jsresolution.ImportResolution,
	name string,
	placeholder jsresolution.PackageIdentity,
	workspaces map[string][]jsresolution.PackageIdentity,
	components npmComponentIndex,
	candidateWork *resolverWorkBudget,
	dst *[]jsresolution.PackageIdentity,
	keepUnknown bool,
) bool {
	if base.Status == jsresolution.StatusAmbiguous {
		for _, candidate := range base.Candidates {
			if candidate.Workspace && candidate.Name == name {
				*dst = append(*dst, candidate)
			}
		}
	} else {
		local := workspaces[name]
		if len(local) > r.limits.maxCandidates || !candidateWork.consumeN(len(local)) {
			return false
		}
		*dst = append(*dst, local...)
	}
	componentCandidates := components.candidates(name)
	if len(componentCandidates) > r.limits.maxCandidates || !candidateWork.consumeN(len(componentCandidates)) {
		return false
	}
	*dst = append(*dst, componentCandidates...)
	if keepUnknown || len(componentCandidates) == 0 {
		*dst = append(*dst, placeholder)
	}
	return true
}

func (r *Resolver) markLockBudgetExceeded(base jsresolution.ImportResolution, budget *resolverWorkBudget, coverage *resolutionCoverageSink) jsresolution.ImportResolution {
	base.Status = jsresolution.StatusUnresolved
	base.Package = jsresolution.PackageIdentity{}
	base.Candidates = nil
	base.Reason = "lockfile importer correlation work budget exceeded"
	if budget != nil && !budget.reported {
		coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: ".", Detail: fmt.Sprintf("lockfile importer correlation work budget exceeded (%d)", r.limits.maxLockWork)})
		budget.reported = true
	}
	return base
}

func isExternalUnmaterialized(identity jsresolution.PackageIdentity) bool {
	return identity.Name != "" && identity.PURL == "" && identity.Path == "" && !identity.Workspace
}
