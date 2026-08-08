package jsresolve

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type npmComponentIndex struct {
	byName        map[string][]jsresolution.PackageIdentity
	byNameVersion map[string]map[string][]jsresolution.PackageIdentity
	coverage      []jsresolution.CoverageIssue
}

func buildNPMComponentIndex(ctx context.Context, doc *sbom.SBOM, limits resolverLimits) (npmComponentIndex, error) {
	out := npmComponentIndex{
		byName:        map[string][]jsresolution.PackageIdentity{},
		byNameVersion: map[string]map[string][]jsresolution.PackageIdentity{},
	}
	if doc == nil {
		return out, nil
	}
	if len(doc.Components) > limits.maxSBOMComponents {
		return npmComponentIndex{}, fmt.Errorf("%w: SBOM component count exceeds resolver budget (%d)", shared.ErrValidation, limits.maxSBOMComponents)
	}
	coverage := resolutionCoverageSink{limit: limits.maxCoverageIssues}
	for _, component := range doc.Components {
		if err := ctx.Err(); err != nil {
			return npmComponentIndex{}, err
		}
		if len(component.Name) > limits.maxSBOMFieldBytes || len(component.Version) > limits.maxSBOMFieldBytes || len(component.PURL) > limits.maxSBOMFieldBytes {
			return npmComponentIndex{}, fmt.Errorf("%w: SBOM component field exceeds resolver budget (%d)", shared.ErrValidation, limits.maxSBOMFieldBytes)
		}
		if component.PURL == "" || !strings.HasPrefix(component.PURL, "pkg:npm/") {
			continue
		}
		name, version, err := parseNPMComponentPURL(component.PURL)
		if err != nil {
			coverage.add(jsresolution.CoverageIssue{
				Kind:   jsresolution.CoverageUnsupportedMetadata,
				Path:   ".",
				Detail: fmt.Sprintf("SBOM npm component PURL %q is not safely correlatable: %v", boundedCoverageText(component.PURL), err),
			})
			continue
		}
		if component.FirstParty {
			continue
		}
		if component.Name != "" {
			declaredName, err := jsresolution.NormalizePackageName(component.Name)
			if err != nil || declaredName != name {
				coverage.add(jsresolution.CoverageIssue{
					Kind:   jsresolution.CoverageUnsupportedMetadata,
					Path:   ".",
					Detail: fmt.Sprintf("SBOM npm component %q disagrees with its PURL package name", boundedCoverageText(component.PURL)),
				})
				continue
			}
		}
		if component.Version != "" && strings.TrimSpace(component.Version) != version {
			coverage.add(jsresolution.CoverageIssue{
				Kind:   jsresolution.CoverageUnsupportedMetadata,
				Path:   ".",
				Detail: fmt.Sprintf("SBOM npm component %q disagrees with its PURL version", boundedCoverageText(component.PURL)),
			})
			continue
		}
		identity := jsresolution.PackageIdentity{Name: name, Version: version, PURL: component.PURL}
		out.byName[name] = append(out.byName[name], identity)
		if out.byNameVersion[name] == nil {
			out.byNameVersion[name] = map[string][]jsresolution.PackageIdentity{}
		}
		out.byNameVersion[name][version] = append(out.byNameVersion[name][version], identity)
	}
	for name := range out.byName {
		sort.Slice(out.byName[name], func(i, j int) bool { return identityLess(out.byName[name][i], out.byName[name][j]) })
		out.byName[name] = deduplicatePackageIdentities(out.byName[name])
		for version := range out.byNameVersion[name] {
			values := out.byNameVersion[name][version]
			sort.Slice(values, func(i, j int) bool { return identityLess(values[i], values[j]) })
			out.byNameVersion[name][version] = deduplicatePackageIdentities(values)
		}
	}
	out.coverage = coverage.issues
	return out, nil
}

func parseNPMComponentPURL(raw string) (string, string, error) {
	purl := strings.TrimSpace(raw)
	if !strings.HasPrefix(purl, "pkg:npm/") {
		return "", "", fmt.Errorf("not an npm PURL")
	}
	identity := strings.TrimPrefix(purl, "pkg:npm/")
	if i := strings.IndexAny(identity, "?#"); i >= 0 {
		identity = identity[:i]
	}
	at := strings.LastIndexByte(identity, '@')
	if at <= 0 || at == len(identity)-1 {
		return "", "", fmt.Errorf("missing package version")
	}
	rawName, rawVersion := identity[:at], identity[at+1:]
	name, err := url.PathUnescape(rawName)
	if err != nil {
		return "", "", fmt.Errorf("decode package name: %w", err)
	}
	version, err := url.PathUnescape(rawVersion)
	if err != nil {
		return "", "", fmt.Errorf("decode package version: %w", err)
	}
	name, err = jsresolution.NormalizePackageName(name)
	if err != nil {
		return "", "", err
	}
	version = strings.TrimSpace(version)
	if !sbom.IsResolvedVersion(version) {
		return "", "", fmt.Errorf("version %q is not resolved", version)
	}
	if identity != canonicalNPMComponentIdentity(name, version) {
		return "", "", fmt.Errorf("npm PURL package identity is not canonical")
	}
	return name, version, nil
}

func canonicalNPMComponentIdentity(name, version string) string {
	purlName := name
	if strings.HasPrefix(purlName, "@") {
		purlName = "%40" + purlName[1:]
	}
	return purlName + "@" + version
}

func boundedCoverageText(value string) string {
	const max = 256
	if len(value) <= max {
		return value
	}
	return value[:max] + "..."
}

func (i npmComponentIndex) candidates(name string) []jsresolution.PackageIdentity {
	return i.byName[name]
}

func (i npmComponentIndex) candidatesVersion(name, version string) []jsresolution.PackageIdentity {
	if i.byNameVersion[name] == nil {
		return nil
	}
	return i.byNameVersion[name][version]
}
