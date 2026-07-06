package ownsbom

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Pnpm is the owned pnpm parser — npm-ecosystem packages resolved by pnpm. It reads the
// FULL resolved set from pnpm-lock.yaml's top-level `packages:` map, whose keys encode each package's
// name@version. The key format varies by lockfile version — v5 `/name/version`, v6 `/name@version(peers)`,
// v9 `name@version` (peers moved to `snapshots:`) — all handled. Rather than pull in a YAML library (the
// owned parsers stay vendor-neutral + dependency-light), it scans for the `packages:` block and reads its
// indent-2 key lines (values, at deeper indent, are ignored — only the keys carry the identity we need).
//
// Components only (edges are not emitted yet). Scope is the manifest path's base scope; the per-workspace
// dev/prod refinement (pnpm hoists all workspaces into one root lock) is applied post-SBOM by the manifest
// enricher's pnpm pass, which runs regardless of the SBOM producer.
type Pnpm struct{}

// Ecosystem identifies this parser's package ecosystem (pnpm resolves npm packages).
func (Pnpm) Ecosystem() string { return "npm" }

// Markers are the lockfile basenames Pnpm claims.
func (Pnpm) Markers() []string { return []string{"pnpm-lock.yaml"} }

// Parse extracts the resolved npm packages from a pnpm-lock.yaml `packages:` block as npm components.
func (Pnpm) Parse(ctx context.Context, in ParseInput) ([]sbom.Component, []sbom.Dependency, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	baseScope := sbom.ClassifyScope(in.Path, "")
	set := newComponentSet()
	inPackages := false
	sc := bufio.NewScanner(bytes.NewReader(in.Content))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		raw := sc.Text()
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue // blank/comment lines don't delimit sections (pnpm-lock blank-separates entries)
		}
		if !indented(raw) { // a col-0 line: a new top-level section. Only `packages:` is ours.
			inPackages = strings.TrimSpace(raw) == "packages:"
			continue
		}
		if !inPackages || leadingIndent(raw) != 2 {
			continue // not in packages, or a deeper value line (resolution/engines/…) — skip
		}
		line := strings.TrimSpace(raw)
		if !strings.HasSuffix(line, ":") {
			continue
		}
		spec := strings.Trim(strings.TrimSuffix(line, ":"), `'"`) // the package key, unquoted (scoped keys quote)
		name, version, ok := pnpmSpecNameVersion(spec)
		if !ok {
			continue
		}
		purlName := name
		if strings.HasPrefix(purlName, "@") {
			purlName = "%40" + purlName[1:] // PURL spec: scoped @ → %40 (matches the npm/yarn parsers)
		}
		set.add(sbom.Component{
			Name:     name,
			Version:  version,
			PURL:     "pkg:npm/" + purlName + "@" + version,
			Location: in.Path,
			Scope:    baseScope,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan pnpm-lock.yaml: %w", err)
	}
	return set.components(), nil, nil
}

// pnpmSpecNameVersion splits a pnpm-lock `packages:` key into (name, version), across lockfile versions:
//
//	v9: lodash@4.17.21 @babel/core@7.23.0
//	v6: /lodash@4.17.21(react@18.0.0) /@babel/core@7.23.0
//	v5: /lodash/4.17.21 /@babel/core/7.23.0
//
// It strips a leading `/` and any `(peer…)` suffix, then splits on the version separator: the last `@`
// AFTER index 0 (v6/v9 — a leading `@` is the scope, not the separator), else the last `/` (v5). The
// version must be a resolved (pinned) version, else the key is dropped.
func pnpmSpecNameVersion(spec string) (name, version string, ok bool) {
	spec = strings.TrimPrefix(spec, "/")
	if i := strings.IndexByte(spec, '('); i >= 0 {
		spec = spec[:i] // drop the peer-deps suffix (v6); it may itself contain '@', so strip before splitting
	}
	sep := -1
	for i := 1; i < len(spec); i++ { // last '@' after index 0 = the v6/v9 separator
		if spec[i] == '@' {
			sep = i
		}
	}
	if sep < 0 { // no '@' after the scope → v5 `name/version`
		sep = strings.LastIndexByte(spec, '/')
	}
	if sep <= 0 || sep == len(spec)-1 {
		return "", "", false
	}
	name, version = spec[:sep], spec[sep+1:]
	if name == "" || !sbom.IsResolvedVersion(version) {
		return "", "", false
	}
	return name, version, true
}
