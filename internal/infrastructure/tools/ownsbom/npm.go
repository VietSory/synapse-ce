package ownsbom

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// maxNPMNestDepth bounds the lockfileVersion-1 nested-dependencies recursion. Go's encoding/json already
// rejects JSON nested past ~10000 before Parse runs, but this makes the parser self-defending rather than
// leaning on that stdlib internal – a transitive tree deeper than this is malicious, so it fails loud.
const maxNPMNestDepth = 1000

// NPM is the owned npm-ecosystem parser (components + edges): it reads package-lock.json – the
// RESOLVED dependency tree – into npm components and, for lockfileVersion 2/3, the dependency edges between
// them. The modern lockfileVersion 2/3 `packages` map (flat, keyed by install path, carrying a `dev` flag
// + the dependency ranges) is the primary source; lockfileVersion 1's nested `dependencies` map is recursed
// as a fallback (COMPONENTS ONLY – v1 edge resolution over the nested tree is a legacy-format follow-up;
// v1 is npm <7, pre-2020). Resolved versions AND the dev/prod scope come straight from the lock, so no
// companion package.json read is needed. Pure JSON parsing, no third-party library, vendor-neutral.
//
// Limitation (honest deferral): a LOCAL workspace/`link` package in a monorepo (a bare non-node_modules
// path like "packages/lib", plus its versionless "link": true symlink entry under node_modules) is not
// emitted as a component – so its outgoing edges are omitted too. This matches the workspace-blind
// convention of the yarn parser + the Syft path; precise monorepo workspace edges are a follow-up.
type NPM struct{}

// Ecosystem identifies this parser's package ecosystem.
func (NPM) Ecosystem() string { return "npm" }

// Markers are the lockfile basenames NPM claims.
func (NPM) Markers() []string { return []string{"package-lock.json"} }

// npmV1Dep is a node in the lockfileVersion-1 nested `dependencies` tree.
type npmV1Dep struct {
	Version      string              `json:"version"`
	Dev          bool                `json:"dev"`
	Integrity    string              `json:"integrity"`
	Dependencies map[string]npmV1Dep `json:"dependencies"`
}

// npmV3Pkg is one entry in the lockfileVersion-2/3 flat `packages` map (keyed by install path). The
// dependency-range maps name this package's direct deps; the RESOLVED version of each is found by walking
// the install path (npm's hoisting – see resolveNpmDep), not from these ranges.
type npmV3Pkg struct {
	Version              string            `json:"version"`
	Dev                  bool              `json:"dev"`
	Integrity            string            `json:"integrity"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

type npmEdgeSpec struct {
	name     string
	scope    string
	optional bool
}

type npmEdgeMeta struct {
	scope    string
	optional bool
}

// Parse extracts the resolved npm packages (+ v2/v3 edges) from a package-lock.json.
func (NPM) Parse(_ context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	var lock struct {
		Packages     map[string]npmV3Pkg `json:"packages"`
		Dependencies map[string]npmV1Dep `json:"dependencies"`
	}
	if err := json.Unmarshal(in.Content, &lock); err != nil {
		return nil, nil, fmt.Errorf("parse package-lock.json: %w", err)
	}
	prodScope := sbom.ClassifyScope(in.Path, "") // production, unless the lock sits under examples/test/etc.
	set := newComponentSet()
	npmPURL := func(name, version string) string {
		// PURL spec: a scoped package @scope/name carries the leading @ percent-encoded as %40 (matches the
		// Syft path + the PURL conformance test), while Component.Name keeps the @scope/name.
		purlName := name
		if strings.HasPrefix(purlName, "@") {
			purlName = "%40" + purlName[1:] 
		}
		return "pkg:npm/" + purlName + "@" + version
	}
	add := func(name, version, integrity string, dev bool) string {
		name = strings.TrimSpace(name)
		scope := prodScope
		if dev {
			scope = sbom.ScopeDevelopment
		}
		purl := npmPURL(name, version)
		set.add(sbom.Component{Name: name, Version: version, PURL: purl, Location: in.Path, Scope: scope, Checksums: parseSubresourceIntegrity(integrity)})
		return purl
	}

	if len(lock.Packages) > 0 {
		pathPURL := make(map[string]string, len(lock.Packages))
		for path, p := range lock.Packages {
			if name := npmNameFromPath(path); name != "" {
				pathPURL[path] = add(name, p.Version, p.Integrity, p.Dev)
			}
		}
		paths := make([]string, 0, len(lock.Packages))
		for path := range lock.Packages {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		var edges []sbom.Dependency
		for _, path := range paths {
			ref, ok := pathPURL[path]
			if !ok {
				continue
			}
			targetMeta := make(map[string]npmEdgeMeta)
			for _, dep := range npmEdgeSpecs(lock.Packages[path], prodScope) {
				tp := resolveNpmDep(path, dep.name, lock.Packages)
				if tp == "" {
					continue
				}
				t := pathPURL[tp]
				if t == "" || t == ref {
					continue
				}
				meta := npmEdgeMeta{scope: dep.scope, optional: dep.optional}
				if existing, exists := targetMeta[t]; exists {
					meta = mergeNPMEdgeMeta(existing, meta)
				}
				targetMeta[t] = meta
			}
			type groupKey struct {
				scope    string
				optional bool
			}
			groups := make(map[groupKey][]string)
			for target, meta := range targetMeta {
				key := groupKey(meta)
				groups[key] = append(groups[key], target)
			}
			keys := make([]groupKey, 0, len(groups))
			for key := range groups {
				keys = append(keys, key)
			}
			sort.Slice(keys, func(i, j int) bool {
				if keys[i].scope != keys[j].scope {
					return keys[i].scope < keys[j].scope
				}
				return !keys[i].optional && keys[j].optional
			})
			for _, key := range keys {
				on := groups[key]
				sort.Strings(on)
				edges = append(edges, sbom.Dependency{Ref: ref, DependsOn: on, Scope: key.scope, Optional: key.optional})
			}
		}
		return set.components(), edges, nil
	}

	var walk func(deps map[string]npmV1Dep, depth int) error
	walk = func(deps map[string]npmV1Dep, depth int) error {
		if depth > maxNPMNestDepth {
			return fmt.Errorf("%w: package-lock.json nesting exceeds %d levels", shared.ErrValidation, maxNPMNestDepth)
		}
		for name, d := range deps {
			add(name, d.Version, d.Integrity, d.Dev)
			if err := walk(d.Dependencies, depth+1); err != nil {
				return err
			}
		return nil
	}
	if err := walk(lock.Dependencies, 0); err != nil {
		return nil, nil, err
	}
	return set.components(), nil, nil
}

func parseSubresourceIntegrity(s string) []sbom.Checksum {
	var out []sbom.Checksum
	for _, tok := range strings.Fields(s) {
		i := strings.IndexByte(tok, '-')
		if i <= 0 || i == len(tok)-1 {
			continue
		}
		out = append(out, sbom.Checksum{Algorithm: strings.ToUpper(tok[:i]), Value: tok[i+1:]})
	}
	return out
}

func npmEdgeSpecs(p npmV3Pkg, prodScope string) []npmEdgeSpec {
	byName := map[string]npmEdgeSpec{}
	for name := range p.Dependencies {
		byName[name] = npmEdgeSpec{name: name, scope: prodScope}
	}
	for name := range p.DevDependencies {
		if _, exists := byName[name]; exists {
			continue
		}
		byName[name] = npmEdgeSpec{name: name, scope: sbom.ScopeDevelopment}
	}
	for name := range p.OptionalDependencies {
		spec := byName[name]
		spec.name = name
		if spec.scope == "" {
			spec.scope = prodScope
		}
		spec.optional = true
		byName[name] = spec
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]npmEdgeSpec, 0, len(names))
	for _, name := range names {
		out = append(out, byName[name])
	}
	return out
}

func mergeNPMEdgeMeta(a, b npmEdgeMeta) npmEdgeMeta {
	out := npmEdgeMeta{scope: a.scope, optional: a.optional && b.optional}
	if a.scope == sbom.ScopeProduction || b.scope == sbom.ScopeProduction {
		out.scope = sbom.ScopeProduction
	} else if a.scope == sbom.ScopeDevelopment || b.scope == sbom.ScopeDevelopment {
		out.scope = sbom.ScopeDevelopment
	} else if out.scope == "" {
		out.scope = b.scope
	}
	return out
}

func resolveNpmDep(fromPath, depName string, packages map[string]npmV3Pkg) string {
	cur := fromPath
	for {
		cand := "node_modules/" + depName
		if cur != "" {
			cand = cur + "/node_modules/" + depName
		}
		if _, ok := packages[cand]; ok {
			return cand
		}
		if cur == "" {
			return ""
		}
		if idx := strings.LastIndex(cur, "/node_modules/"); idx >= 0 {
			cur = cur[:idx]
		} else {
			cur = ""
		}
	}
}

func npmNameFromPath(p string) string {
	const nm = "node_modules/"
	i := strings.LastIndex(p, nm)
	if i < 0 {
		return ""
	}
	return p[i+len(nm):]
}
