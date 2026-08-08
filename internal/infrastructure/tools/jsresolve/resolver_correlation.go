package jsresolve

import (
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
)

func externalPlaceholders(resolution jsresolution.ImportResolution) []jsresolution.PackageIdentity {
	if resolution.Status == jsresolution.StatusUnresolved {
		if isExternalPlaceholder(resolution.Package) {
			return []jsresolution.PackageIdentity{resolution.Package}
		}
		return nil
	}
	seen := map[string]struct{}{}
	var out []jsresolution.PackageIdentity
	for _, candidate := range resolution.Candidates {
		if !isExternalPlaceholder(candidate) {
			continue
		}
		if _, ok := seen[candidate.Name]; ok {
			continue
		}
		seen[candidate.Name] = struct{}{}
		out = append(out, candidate)
	}
	sort.Slice(out, func(i, j int) bool { return identityLess(out[i], out[j]) })
	return out
}

func isExternalPlaceholder(identity jsresolution.PackageIdentity) bool {
	return identity.Name != "" && identity.Version == "" && identity.PURL == "" && identity.Path == "" && !identity.Workspace
}

func isSamePackageSelfReference(resolution jsresolution.ImportResolution, packages []jsresolution.PackageMetadata) bool {
	classified := jsresolution.ClassifySpecifier(resolution.Specifier)
	if classified.Kind != jsresolution.SpecifierPackage || resolution.Package.Name == "" {
		return false
	}
	pkg, ok := packageForRepositoryTarget(packages, resolution.From)
	return ok && pkg.Name != "" && pkg.Name == classified.PackageName && resolution.Package.Name == classified.PackageName
}

func addFinalEdgeCoverage(dst *resolutionCoverageSink, issues []jsresolution.CoverageIssue, before, after jsresolution.Status) {
	resolvedByCorrelation := (before == jsresolution.StatusUnresolved || before == jsresolution.StatusAmbiguous) &&
		(after == jsresolution.StatusWorkspace || after == jsresolution.StatusComponent)
	for _, issue := range issues {
		if resolvedByCorrelation && (issue.Kind == jsresolution.CoverageUnresolvedSpecifier || issue.Kind == jsresolution.CoverageUnresolvedAlias) {
			continue
		}
		dst.add(issue)
	}
}
