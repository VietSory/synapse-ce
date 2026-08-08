package jsresolve

import "sort"

// makePackageScopesGloballyUncertain prevents a truncated alias/package-scope
// walk from turning absence of an observed boundary into evidence that no nearer
// package.json exists. Every known boundary becomes uncertain and a synthetic
// root boundary covers importers whose actual nearer boundary may have been
// skipped entirely.
func makePackageScopesGloballyUncertain(contexts []aliasPackageContext) []aliasPackageContext {
	out := append([]aliasPackageContext(nil), contexts...)
	for i := range out {
		out[i].uncertain = true
	}
	out = append(out, aliasPackageContext{source: ".", scopeDir: ".", uncertain: true})
	sort.Slice(out, func(i, j int) bool {
		if out[i].scopeDir != out[j].scopeDir {
			return out[i].scopeDir < out[j].scopeDir
		}
		return out[i].source < out[j].source
	})
	return deduplicateAliasPackageContexts(out)
}
