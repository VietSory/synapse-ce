package ownsbom

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Poetry is the owned Python-via-Poetry parser (components + edges): it reads poetry.lock — the
// resolved dependency set as TOML [[package]] blocks — into pypi components (pkg:pypi/<name>@<version>) AND
// the dependency edges between them. Resolved versions come from the lock; the dev/prod scope comes from the
// block's `category = "dev"` (Poetry <1.5, inline) when present, else the file path. Names are PEP 503-
// normalized (shared with the requirements parser). Each package's `[package.dependencies]` sub-table names
// its direct deps; each dep is resolved to the matching [[package]]'s PURL — a dep with no [[package]] entry
// (e.g. the `python` constraint, or an extras-only marker) yields no edge, so an odd/unparsed entry is
// silently dropped rather than mis-linked. Reuses the [[package]] scan (shared with Cargo) — hand-parsed, no
// TOML library, vendor-neutral.
type Poetry struct{}

// Ecosystem identifies this parser's package ecosystem (Poetry resolves PyPI packages).
func (Poetry) Ecosystem() string { return "pypi" }

// Markers are the lockfile basenames Poetry claims.
func (Poetry) Markers() []string { return []string{"poetry.lock"} }

// poetryPkg is a [[package]] block collected in pass 1: identity + the direct dependency names from its
// [package.dependencies] sub-table (resolved to edges in pass 2).
type poetryPkg struct {
	name, version, category string
	deps                    []string // raw direct-dependency names from [package.dependencies]
}

// Parse extracts the resolved packages + their dependency edges from a poetry.lock.
func (Poetry) Parse(_ context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	baseScope := sbom.ClassifyScope(in.Path, "")

	// Pass 1: collect the [[package]] blocks (identity + the direct dep names from [package.dependencies];
	// a dep can reference a package defined later in the file, so edges are resolved in pass 2).
	var pkgs []poetryPkg
	var cur poetryPkg
	inPkg, inDeps := false, false
	flush := func() {
		if cur.name != "" && cur.version != "" {
			pkgs = append(pkgs, cur)
		}
		cur, inDeps = poetryPkg{}, false
	}
	sc := bufio.NewScanner(bytes.NewReader(in.Content))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "[[package]]":
			flush() // close the previous package block
			inPkg = true
		case line == "[package.dependencies]":
			inDeps = true // the current package's direct deps follow — stay associated with cur (do NOT flush)
		case strings.HasPrefix(line, "["): // any other table ([package.extras]/[package.source]/[metadata]/…) ends the block
			flush()
			inPkg = false
		case inDeps && strings.ContainsRune(line, '='):
			// a dep entry `name = "constraint"` or `name = {version=…}`: the KEY (before the first =) is the
			// dep name. A non-package-name key (e.g. a "{" array element) is filtered; an unresolvable name
			// produces no edge in pass 2, so a stray entry is harmless.
			if k := strings.Trim(strings.TrimSpace(line[:strings.IndexByte(line, '=')]), `"`); isPoetryDepKey(k) {
				cur.deps = append(cur.deps, k)
			}
		case inPkg && strings.HasPrefix(line, "name = "):
			cur.name = tomlString(line[len("name = "):])
		case inPkg && strings.HasPrefix(line, "version = "):
			cur.version = tomlString(line[len("version = "):])
		case inPkg && strings.HasPrefix(line, "category = "):
			cur.category = tomlString(line[len("category = "):])
		}
	}
	flush() // the final package block
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan poetry.lock: %w", err)
	}

	// Index normalized name -> resolved version(s). A real poetry.lock is deduped (one version per name); a
	// name mapping to MORE than one version (a malformed/crafted lock) is ambiguous and resolves to NO edge,
	// mirroring Cargo's resolver — never guess which same-named package an edge points at.
	purlOf := func(name, version string) string { return "pkg:pypi/" + name + "@" + version }
	versionsOf := map[string][]string{}
	for _, p := range pkgs {
		n := normalizePyPI(p.name)
		versionsOf[n] = append(versionsOf[n], p.version)
	}

	// Pass 2: emit components + resolve edges.
	set := newComponentSet()
	var deps []sbom.Dependency
	for _, p := range pkgs {
		n := normalizePyPI(p.name)
		scope := baseScope
		if strings.EqualFold(p.category, "dev") {
			scope = sbom.ScopeDevelopment
		}
		ref := purlOf(n, p.version)
		set.add(sbom.Component{Name: n, Version: p.version, PURL: ref, Location: in.Path, Scope: scope})
		seen := map[string]bool{ref: true} // drop self-edges + duplicate targets
		var on []string
		for _, d := range p.deps {
			dn := normalizePyPI(d)
			vs := versionsOf[dn]
			if len(vs) != 1 {
				continue // no [[package]] entry (e.g. the python constraint) OR an ambiguous duplicate name — no edge
			}
			if t := purlOf(dn, vs[0]); !seen[t] {
				seen[t] = true
				on = append(on, t)
			}
		}
		if len(on) > 0 {
			deps = append(deps, sbom.Dependency{Ref: ref, DependsOn: on})
		}
	}
	return set.components(), deps, nil
}

// isPoetryDepKey reports whether a [package.dependencies] line's key is a package-name token (starts
// alphanumeric) — filtering multi-line-value continuation lines (e.g. an array element starting with "{").
func isPoetryDepKey(k string) bool {
	if k == "" {
		return false
	}
	c := k[0]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
