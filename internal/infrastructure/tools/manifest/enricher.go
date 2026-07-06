// Package manifest enriches a generator's SBOM from dependency manifests the
// generator under-uses: it reconstructs missing dependency edges
// (Gemfile.lock), recovers dependencies the generator cannot resolve from source
// (Maven pom.xml, Gradle version catalogs), and refines component scope via pnpm
// workspace attribution. It reads only files already in the acquired workspace —
// no execution, no network.
package manifest

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownsbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const maxManifestBytes = 16 << 20 // cap a single manifest read

// Enricher implements ports.SBOMEnricher over the workspace's manifest files.
type Enricher struct{}

// New returns a manifest enricher.
func New() *Enricher { return &Enricher{} }

var _ ports.SBOMEnricher = (*Enricher)(nil)

// Enrich augments doc in place and reports what it contributed.
func (Enricher) Enrich(ctx context.Context, dir string, doc *sbom.SBOM) ports.SBOMEnrichment {
	var res ports.SBOMEnrichment
	if doc == nil {
		return res
	}
	var gemEdges []sbom.Dependency
	var mavenComps, gradleComps []sbom.Component
	pnpmScopes := map[string]string{}

	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		switch strings.ToLower(d.Name()) {
		case "gemfile.lock":
			if data := read(path); data != nil {
				gemEdges = append(gemEdges, parseGemfileLockEdges(data)...)
			}
		case "pom.xml":
			if data := read(path); data != nil {
				mavenComps = append(mavenComps, parsePomComponents(data)...)
			}
		case "libs.versions.toml":
			if data := read(path); data != nil {
				// Delegate to the SHARED owned Gradle parser — one implementation for both the owned
				// SBOM producer (ownsbom.Gradle) and this Syft-enrichment path; no duplicated catalog parser.
				gradleComps = append(gradleComps, ownsbom.ParseGradleCatalog(data)...)
			}
		case "pnpm-lock.yaml":
			if data := read(path); data != nil {
				for k, v := range parsePnpmScopes(data) {
					if cur, ok := pnpmScopes[k]; !ok || scopeRank(v) > scopeRank(cur) {
						pnpmScopes[k] = v
					}
				}
			}
		}
		return nil
	})

	res.ComponentsAdded = mergeComponents(doc, append(mavenComps, gradleComps...))
	res.EdgesAdded = mergeEdges(doc, gemEdges)
	res.ScopesRefined = refineScopes(doc, pnpmScopes)
	res.Sources = sourcesUsed(gemEdges, mavenComps, gradleComps, pnpmScopes)
	return res
}

// mergeComponents adds components the generator missed (by name@version identity).
func mergeComponents(doc *sbom.SBOM, extra []sbom.Component) int {
	have := make(map[string]bool, len(doc.Components))
	for _, c := range doc.Components {
		have[c.Name+"@"+c.Version] = true
	}
	added := 0
	for _, c := range extra {
		key := c.Name + "@" + c.Version
		if c.Name == "" || have[key] {
			continue
		}
		have[key] = true
		doc.Components = append(doc.Components, c)
		added++
	}
	return added
}

// mergeEdges adds reconstructed dependency edges not already present.
func mergeEdges(doc *sbom.SBOM, extra []sbom.Dependency) int {
	have := make(map[string]bool, len(doc.Dependencies))
	for _, d := range doc.Dependencies {
		have[d.Ref] = true
	}
	added := 0
	for _, e := range extra {
		if have[e.Ref] {
			continue // generator already provided this node's edges
		}
		have[e.Ref] = true
		doc.Dependencies = append(doc.Dependencies, e)
		added += len(e.DependsOn)
	}
	return added
}

// refineScopes re-scopes components when pnpm workspace attribution says a dep is
// only used by a background workspace (and the current scope is less specific).
func refineScopes(doc *sbom.SBOM, scopes map[string]string) int {
	if len(scopes) == 0 {
		return 0
	}
	refined := 0
	for i := range doc.Components {
		c := &doc.Components[i]
		s, ok := scopes[c.Name+"@"+c.Version]
		if !ok {
			continue
		}
		// Only move toward MORE background (lower rank) — never upgrade a
		// directory-derived background scope back to production.
		if scopeRank(s) < scopeRank(orDefault(c.Scope)) {
			c.Scope = s
			refined++
		}
	}
	return refined
}

func orDefault(s string) string {
	if s == "" {
		return sbom.ScopeUnknown
	}
	return s
}

func sourcesUsed(gem []sbom.Dependency, maven, gradle []sbom.Component, pnpm map[string]string) []string {
	var s []string
	if len(gem) > 0 {
		s = append(s, "gemfile")
	}
	if len(maven) > 0 {
		s = append(s, "maven")
	}
	if len(gradle) > 0 {
		s = append(s, "gradle")
	}
	if len(pnpm) > 0 {
		s = append(s, "pnpm")
	}
	return s
}

func read(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxManifestBytes))
	if err != nil {
		return nil
	}
	return data
}
