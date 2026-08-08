package jsresolve

import (
	"context"
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
)

func (r *Resolver) identitiesForFinalLockSelections(
	ctx context.Context,
	base jsresolution.ImportResolution,
	name string,
	selections []lockSelection,
	workspaces map[string][]jsresolution.PackageIdentity,
	components npmComponentIndex,
	candidateWork *resolverWorkBudget,
	coverage *resolutionCoverageSink,
) ([]jsresolution.PackageIdentity, []jsresolution.PackageIdentity) {
	var resolved []jsresolution.PackageIdentity
	var missing []jsresolution.PackageIdentity
	for _, selection := range selections {
		if err := ctx.Err(); err != nil {
			return nil, []jsresolution.PackageIdentity{{Name: name}}
		}
		switch selection.kind {
		case lockSelectionWorkspace:
			local := workspaces[name]
			if len(local) > r.limits.maxCandidates || !candidateWork.consumeN(len(local)) {
				if candidateWork != nil {
					candidateWork.exceeded = true
				}
				return nil, nil
			}
			matched := false
			for _, candidate := range local {
				if candidate.Path == selection.workspacePath {
					resolved = append(resolved, candidate)
					matched = true
				}
			}
			if !matched {
				missing = append(missing, jsresolution.PackageIdentity{Name: name})
				coverage.add(jsresolution.CoverageIssue{
					Kind: jsresolution.CoverageUnsupportedMetadata, Path: selection.source,
					Detail: fmt.Sprintf("%s lock selection for %q points to unobserved workspace %q", selection.manager, name, selection.workspacePath),
				})
			}
		case lockSelectionExternal:
			matched := components.candidatesVersion(name, selection.version)
			if len(matched) == 0 {
				missing = append(missing, jsresolution.PackageIdentity{Name: name, Version: selection.version})
				coverage.add(jsresolution.CoverageIssue{
					Kind: jsresolution.CoverageMissingSBOMComponent, Path: base.From,
					Detail: fmt.Sprintf("%s lock selects %s@%s but the supplied SBOM has no matching npm PURL", selection.manager, name, selection.version),
				})
				continue
			}
			if len(matched) > r.limits.maxCandidates || !candidateWork.consumeN(len(matched)) {
				if candidateWork != nil {
					candidateWork.exceeded = true
				}
				return nil, nil
			}
			resolved = append(resolved, matched...)
		case lockSelectionUnsupported:
			missing = append(missing, jsresolution.PackageIdentity{Name: name})
		}
	}
	sort.Slice(resolved, func(i, j int) bool { return identityLess(resolved[i], resolved[j]) })
	sort.Slice(missing, func(i, j int) bool { return identityLess(missing[i], missing[j]) })
	return deduplicatePackageIdentities(resolved), deduplicatePackageIdentities(missing)
}
