package jsresolve

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
	"sort"
	"strings"
)

func packageContextForImporter(contexts []aliasPackageContext, importer string) (aliasPackageContext, bool) {
	var best aliasPackageContext
	bestDepth := -1
	found := false
	for _, context := range contexts {
		if !pathWithin(context.scopeDir, importer) {
			continue
		}
		depth := repositoryDepth(context.scopeDir)
		if !found || depth > bestDepth || (depth == bestDepth && context.source < best.source) {
			best, bestDepth, found = context, depth, true
		}
	}
	return best, found
}

func packageForRepositoryTarget(packages []jsresolution.PackageMetadata, target string) (jsresolution.PackageMetadata, bool) {
	for _, pkg := range packages {
		if pathWithin(pkg.Path, target) {
			return pkg, true
		}
	}
	return jsresolution.PackageMetadata{}, false
}

func packageMetadataIdentity(pkg jsresolution.PackageMetadata) jsresolution.PackageIdentity {
	return jsresolution.PackageIdentity{
		Name: pkg.Name, Version: pkg.Version, Workspace: pkg.Workspace, Path: pkg.Path,
	}
}

func pathWithin(scope, candidate string) bool {
	if scope == "" || scope == "." {
		return candidate != "" && candidate != ".." && !strings.HasPrefix(candidate, "../")
	}
	return candidate == scope || strings.HasPrefix(candidate, scope+"/")
}

func containsPathSegment(value, segment string) bool {
	for _, part := range strings.Split(value, "/") {
		if part == segment {
			return true
		}
	}
	return false
}

func relativeEdgeHasCoverage(coverage []modulegraph.CoverageIssue, edge modulegraph.Edge) bool {
	for _, issue := range coverage {
		if issue.Path != edge.From {
			continue
		}
		if edge.Position.Line > 0 && issue.Line != edge.Position.Line {
			continue
		}
		switch issue.Kind {
		case modulegraph.CoverageUnresolvedRelativeImport, modulegraph.CoverageAmbiguousRelativeImport, modulegraph.CoverageRelativeImportEscapesRoot:
			return true
		}
	}
	return false
}

func repositoryDepth(value string) int {
	if value == "" || value == "." {
		return 0
	}
	return strings.Count(value, "/") + 1
}

func identityLess(a, b jsresolution.PackageIdentity) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	if a.PURL != b.PURL {
		return a.PURL < b.PURL
	}
	if a.Workspace != b.Workspace {
		return !a.Workspace && b.Workspace
	}
	return a.Path < b.Path
}

func deduplicatePackageIdentities(in []jsresolution.PackageIdentity) []jsresolution.PackageIdentity {
	if len(in) < 2 {
		return in
	}
	out := in[:1]
	for _, value := range in[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func deduplicateAliasOutcomes(in []resolvedAliasTarget) []resolvedAliasTarget {
	if len(in) < 2 {
		return in
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].status != in[j].status {
			return in[i].status < in[j].status
		}
		return identityLess(in[i].identity, in[j].identity)
	})
	out := in[:1]
	for _, value := range in[1:] {
		last := out[len(out)-1]
		if value.status != last.status || value.identity != last.identity {
			out = append(out, value)
		}
	}
	return out
}
