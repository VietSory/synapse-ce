package jsresolve

import (
	"sort"
	"strings"
)

// selectionsForPackage returns importer selections from the nearest observed
// lockfile scope, but only for the importer's nearest package.json boundary.
// A parent project's root dependency must never leak through a nested package
// boundary that the parent lock does not actually model as an importer.
func (c lockContext) selectionsForPackage(
	importer, name string,
	packageScopes []aliasPackageContext,
	work *resolverWorkBudget,
) (selections []lockSelection, found, uncertain, exhausted bool) {
	pkg, ok := packageContextForImporter(packageScopes, importer)
	if !ok {
		return nil, false, false, false
	}
	if pkg.uncertain {
		return nil, true, true, false
	}
	packageDir := pkg.scopeDir
	manifestUnsafe := false

	for lockDir := packageDir; ; {
		if work != nil && !work.consume() {
			return nil, false, false, true
		}
		contexts := lockSourcesAtDir(c.sources, lockDir)
		if len(contexts) > 0 {
			var actual []lockSourceContext
			for _, source := range contexts {
				if strings.HasPrefix(source.manager, manifestGuardPrefix) {
					guardName := strings.TrimPrefix(source.manager, manifestGuardPrefix)
					if guardName == "*" || guardName == name {
						manifestUnsafe = true
					}
					continue
				}
				actual = append(actual, source)
			}
			if len(actual) > 0 {
				var out []lockSelection
				actualUncertain := false
				for _, source := range actual {
					if work != nil && !work.consume() {
						return nil, true, actualUncertain || manifestUnsafe, true
					}
					if source.uncertain {
						actualUncertain = true
						continue
					}
					values := c.bindings[lockBindingKey(source.source, packageDir, name)]
					if work != nil && !work.consumeN(len(values)) {
						return nil, true, actualUncertain || manifestUnsafe, true
					}
					for _, value := range values {
						if value.kind == lockSelectionUnsupported {
							actualUncertain = true
						}
					}
					out = append(out, values...)
				}
				sort.Slice(out, func(i, j int) bool { return lockSelectionLess(out[i], out[j]) })
				out = deduplicateLockSelections(out)
				if len(out) > 0 && !actualUncertain {
					if !manifestUnsafe || allWorkspaceSelections(out) {
						return out, true, false, false
					}
					// A manifest protocol that can change package identity (file:, git:,
					// workspace:, etc.) cannot be erased by an external lock entry that
					// may simply be stale. A verified workspace selection is the only
					// safe override at this layer.
					return out, true, true, false
				}
				return out, true, actualUncertain || manifestUnsafe, false
			}
		}
		parent, ok := parentRepositoryLocation(lockDir)
		if !ok {
			if manifestUnsafe {
				return nil, true, true, false
			}
			return nil, false, false, false
		}
		lockDir = parent
	}
}

func allWorkspaceSelections(values []lockSelection) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if value.kind != lockSelectionWorkspace {
			return false
		}
	}
	return true
}
