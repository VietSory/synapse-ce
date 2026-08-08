package jsresolve

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

type yarnLockEntry struct {
	descriptors    []string
	version        string
	resolution     string
	versionSeen    bool
	resolutionSeen bool
	malformed      bool
}

type yarnDescriptorVersionIndex struct {
	versions map[string][]string
	invalid  map[string]struct{}
	coverage []jsresolution.CoverageIssue
}

func parseYarnLockSelections(ctx context.Context, raw rawLockFile, manifests map[string]packageRequests, workspaces map[string][]jsresolution.PackageIdentity, limits resolverLimits) ([]lockSelection, []jsresolution.CoverageIssue, error) {
	descriptorVersions, err := parseYarnDescriptorVersions(ctx, raw, limits)
	if err != nil {
		return nil, nil, err
	}
	manifestDirs := make([]string, 0, len(manifests))
	for dir := range manifests {
		if !pathWithin(raw.dir, dir) || !yarnManagedImporter(raw.dir, dir, workspaces) {
			continue
		}
		manifestDirs = append(manifestDirs, dir)
	}
	sort.Strings(manifestDirs)
	var selections []lockSelection
	issues := resolutionCoverageSink{limit: limits.maxCoverageIssues}
	issues.addAll(descriptorVersions.coverage)
	appendUnsupported := func(importer, name, source, detail string) {
		selections = append(selections, lockSelection{kind: lockSelectionUnsupported, manager: "yarn", source: raw.source, importer: importer, name: name})
		issues.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedMetadata, Path: source, Detail: detail})
	}
	for _, importer := range manifestDirs {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		manifest := manifests[importer]
		if manifest.uncertain {
			continue
		}
		names := make([]string, 0, len(manifest.dependencies))
		for name := range manifest.dependencies {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			request := strings.TrimSpace(manifest.dependencies[name])
			local := workspaces[name]
			if strings.HasPrefix(request, "workspace:") {
				if len(local) == 0 {
					appendUnsupported(importer, name, manifest.source, fmt.Sprintf("Yarn workspace request for %q has no observed workspace", name))
					continue
				}
				for _, candidate := range local {
					selections = append(selections, lockSelection{kind: lockSelectionWorkspace, manager: "yarn", source: raw.source, importer: importer, name: name, workspacePath: candidate.Path})
				}
				continue
			}
			if !yarnRequestIsNPMRegistry(name, request) {
				appendUnsupported(importer, name, manifest.source, fmt.Sprintf("Yarn dependency %q uses non-registry or aliased request %q that R2C does not correlate to npm PURLs", name, boundedCoverageText(request)))
				continue
			}

			if len(local) > 0 {
				requestVersion := strings.TrimSpace(strings.TrimPrefix(request, "npm:"))
				if sbom.IsResolvedVersion(requestVersion) {
					localCanMatch := false
					for _, candidate := range local {
						if candidate.Version == requestVersion {
							localCanMatch = true
							break
						}
					}
					if !localCanMatch {
						versions, invalid := yarnResolvedVersions(descriptorVersions, name, request)
						if invalid {
							appendUnsupported(importer, name, raw.source, fmt.Sprintf("yarn.lock has inconsistent metadata for %s@%s", name, boundedCoverageText(request)))
							continue
						}
						if len(versions) == 0 {
							appendUnsupported(importer, name, raw.source, fmt.Sprintf("yarn.lock has no resolved descriptor for %s@%s", name, boundedCoverageText(request)))
							continue
						}
						for _, version := range versions {
							selections = append(selections, lockSelection{kind: lockSelectionExternal, manager: "yarn", source: raw.source, importer: importer, name: name, version: version})
						}
					}
				}
				// A plain range/exact request that can be satisfied by a same-name
				// workspace is not enough to prove local selection across Yarn
				// configurations. Only the explicit workspace: protocol is definitive.
				continue
			}

			versions, invalid := yarnResolvedVersions(descriptorVersions, name, request)
			if invalid {
				appendUnsupported(importer, name, raw.source, fmt.Sprintf("yarn.lock has inconsistent metadata for %s@%s", name, boundedCoverageText(request)))
				continue
			}
			if len(versions) == 0 {
				appendUnsupported(importer, name, raw.source, fmt.Sprintf("yarn.lock has no resolved descriptor for %s@%s", name, boundedCoverageText(request)))
				continue
			}
			for _, version := range versions {
				selections = append(selections, lockSelection{kind: lockSelectionExternal, manager: "yarn", source: raw.source, importer: importer, name: name, version: version})
			}
		}
	}
	if len(selections) > limits.maxLockBindings {
		return nil, issues.issues, fmt.Errorf("yarn lock selection budget exceeded (%d)", limits.maxLockBindings)
	}
	return selections, issues.issues, nil
}

// yarnManagedImporter keeps Yarn correlation within the project described by
// the lockfile. Unlike npm/pnpm, yarn.lock has no explicit importer table; using
// every nested package.json would let an unrelated nested project borrow the
// root lock and manufacture a version selection. The lock root itself and
// observed workspace package roots are the only safe importer contexts here.
func yarnManagedImporter(lockDir, importer string, workspaces map[string][]jsresolution.PackageIdentity) bool {
	if importer == lockDir {
		return true
	}
	for _, candidates := range workspaces {
		for _, candidate := range candidates {
			if candidate.Workspace && candidate.Path == importer && pathWithin(lockDir, importer) {
				return true
			}
		}
	}
	return false
}

// yarnRequestIsNPMRegistry accepts only requests whose identity remains the
// dependency key's npm package name. Yarn's npm: protocol can directly wrap a
// resolved version (for example npm:4.17.21); that form is not a package alias.
func yarnRequestIsNPMRegistry(name, request string) bool {
	request = strings.TrimSpace(request)
	if request == "" || strings.HasPrefix(request, "workspace:") {
		return false
	}
	if strings.HasPrefix(request, "npm:") {
		target := strings.TrimSpace(strings.TrimPrefix(request, "npm:"))
		if target == "" {
			return false
		}
		if sbom.IsResolvedVersion(target) {
			return true
		}
		if targetName := packageAliasTargetName(target); targetName != "" {
			normalized, err := jsresolution.NormalizePackageName(targetName)
			return err == nil && normalized == name
		}
		return true
	}
	if strings.Contains(request, ":") || strings.Contains(request, "/") || strings.HasPrefix(request, ".") {
		return false
	}
	return true
}

func parseYarnDescriptorVersions(ctx context.Context, raw rawLockFile, limits resolverLimits) (yarnDescriptorVersionIndex, error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw.content))
	scanner.Buffer(make([]byte, 0, 64*1024), limits.maxLockLineBytes)
	var entries []yarnLockEntry
	descriptorCount := 0
	var current *yarnLockEntry
	metadataSeen := false
	metadataVersion := ""
	metadataVersionSeen := false
	inMetadata := false
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return yarnDescriptorVersionIndex{}, err
		}
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !yarnIndented(rawLine) {
			current = nil
			inMetadata = false
			if line == "__metadata:" {
				if metadataSeen {
					return yarnDescriptorVersionIndex{}, fmt.Errorf("yarn.lock has duplicate __metadata sections")
				}
				metadataSeen = true
				inMetadata = true
				continue
			}
			if !strings.HasSuffix(line, ":") {
				continue
			}
			descriptors := yarnLockDescriptors(line)
			if len(descriptors) == 0 {
				continue
			}
			if len(descriptors) > limits.maxLockBindings-descriptorCount {
				return yarnDescriptorVersionIndex{}, fmt.Errorf("yarn descriptor count exceeds budget (%d)", limits.maxLockBindings)
			}
			descriptorCount += len(descriptors)
			current = &yarnLockEntry{descriptors: descriptors}
			entries = append(entries, *current)
			current = &entries[len(entries)-1]
			if len(entries) > limits.maxLockEntries {
				return yarnDescriptorVersionIndex{}, fmt.Errorf("yarn lock entry count exceeds budget (%d)", limits.maxLockEntries)
			}
			continue
		}
		indent, _ := yamlIndent(rawLine)
		if current == nil {
			if inMetadata && indent == 2 && strings.HasPrefix(line, "version:") {
				if metadataVersionSeen {
					return yarnDescriptorVersionIndex{}, fmt.Errorf("yarn.lock __metadata has duplicate version fields")
				}
				metadataVersionSeen = true
				metadataVersion = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "version:")), `"' `)
			}
			continue
		}
		if indent != 2 {
			continue
		}
		switch {
		case strings.HasPrefix(line, "version "):
			if current.versionSeen {
				current.malformed = true
				continue
			}
			current.versionSeen = true
			current.version = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "version")), `:" `)
		case strings.HasPrefix(line, "version:"):
			if current.versionSeen {
				current.malformed = true
				continue
			}
			current.versionSeen = true
			current.version = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "version:")), `" `)
		case strings.HasPrefix(line, "resolution:"):
			if current.resolutionSeen {
				current.malformed = true
				continue
			}
			current.resolutionSeen = true
			current.resolution = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "resolution:")), `" `)
		}
	}
	if err := scanner.Err(); err != nil {
		return yarnDescriptorVersionIndex{}, fmt.Errorf("scan yarn.lock: %w", err)
	}
	if metadataSeen {
		if !metadataVersionSeen {
			return yarnDescriptorVersionIndex{}, fmt.Errorf("yarn.lock __metadata has no version field")
		}
		if metadataVersion != "8" && metadataVersion != "10" {
			return yarnDescriptorVersionIndex{}, fmt.Errorf("%w: yarn.lock metadata version %q is outside supported versions 8 and 10", errUnsupportedYarnLockLayout, boundedCoverageText(metadataVersion))
		}
	}
	invalidCoverage := resolutionCoverageSink{limit: limits.maxCoverageIssues}
	out := yarnDescriptorVersionIndex{versions: map[string][]string{}, invalid: map[string]struct{}{}}
	descriptorSeen := map[string]struct{}{}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return yarnDescriptorVersionIndex{}, err
		}
		version := strings.TrimSpace(entry.version)
		for _, descriptor := range entry.descriptors {
			if strings.Contains(descriptor, "@workspace:") {
				continue
			}
			name := yarnLockSpecName(descriptor)
			if name == "" {
				continue
			}
			request := strings.TrimPrefix(descriptor, name+"@")
			if !yarnRequestIsNPMRegistry(name, request) {
				continue
			}
			if _, duplicate := descriptorSeen[descriptor]; duplicate {
				out.invalid[descriptor] = struct{}{}
				invalidCoverage.add(jsresolution.CoverageIssue{
					Kind:   jsresolution.CoverageMalformedMetadata,
					Path:   raw.source,
					Detail: fmt.Sprintf("yarn.lock repeats descriptor %q in multiple entries", boundedCoverageText(descriptor)),
				})
				continue
			}
			descriptorSeen[descriptor] = struct{}{}
			if entry.malformed {
				out.invalid[descriptor] = struct{}{}
				invalidCoverage.add(jsresolution.CoverageIssue{
					Kind:   jsresolution.CoverageMalformedMetadata,
					Path:   raw.source,
					Detail: fmt.Sprintf("yarn.lock descriptor %q repeats a correlated field", boundedCoverageText(descriptor)),
				})
				continue
			}
			if !entry.versionSeen || !sbom.IsResolvedVersion(version) {
				out.invalid[descriptor] = struct{}{}
				invalidCoverage.add(jsresolution.CoverageIssue{
					Kind:   jsresolution.CoverageMalformedMetadata,
					Path:   raw.source,
					Detail: fmt.Sprintf("yarn.lock descriptor %q has no resolved version", boundedCoverageText(descriptor)),
				})
				continue
			}
			if entry.resolution != "" {
				resolvedName, resolvedVersion, ok := yarnNPMResolutionIdentity(entry.resolution)
				if !ok || resolvedName != name || resolvedVersion != version {
					out.invalid[descriptor] = struct{}{}
					invalidCoverage.add(jsresolution.CoverageIssue{
						Kind: jsresolution.CoverageUnsupportedMetadata,
						Path: raw.source,
						Detail: fmt.Sprintf("yarn.lock descriptor %q has inconsistent resolution locator %q for version %q",
							boundedCoverageText(descriptor), boundedCoverageText(entry.resolution), boundedCoverageText(version)),
					})
					continue
				}
			}
			out.versions[descriptor] = append(out.versions[descriptor], version)
		}
	}
	for descriptor := range out.versions {
		sort.Strings(out.versions[descriptor])
		out.versions[descriptor] = deduplicateStrings(out.versions[descriptor])
	}
	out.coverage = invalidCoverage.issues
	return out, nil
}

func yarnNPMResolutionIdentity(value string) (string, string, bool) {
	value = strings.Trim(strings.TrimSpace(value), `"`)
	separator := strings.Index(value, "@npm:")
	if separator <= 0 {
		return "", "", false
	}
	name, err := jsresolution.NormalizePackageName(value[:separator])
	if err != nil {
		return "", "", false
	}
	version := value[separator+len("@npm:"):]
	if index := strings.Index(version, "::"); index >= 0 {
		version = version[:index]
	}
	version = strings.TrimSpace(version)
	if !sbom.IsResolvedVersion(version) {
		return "", "", false
	}
	return name, version, true
}

func yarnLockDescriptors(keyLine string) []string {
	key := strings.TrimSuffix(strings.TrimSpace(keyLine), ":")
	var out []string
	for _, part := range strings.Split(key, ",") {
		descriptor := strings.Trim(strings.TrimSpace(part), `"`)
		if descriptor != "" && yarnLockSpecName(descriptor) != "" {
			out = append(out, descriptor)
		}
	}
	sort.Strings(out)
	return deduplicateStrings(out)
}

func yarnLockSpecName(spec string) string {
	for i := 1; i < len(spec); i++ {
		if spec[i] == '@' {
			return spec[:i]
		}
	}
	return ""
}

func yarnResolvedVersions(index yarnDescriptorVersionIndex, name, request string) ([]string, bool) {
	keys := []string{name + "@" + request}
	if !strings.HasPrefix(request, "npm:") {
		keys = append(keys, name+"@npm:"+request)
	}
	var out []string
	invalid := false
	for _, key := range keys {
		if _, bad := index.invalid[key]; bad {
			invalid = true
		}
		out = append(out, index.versions[key]...)
	}
	sort.Strings(out)
	return deduplicateStrings(out), invalid
}

func yarnIndented(raw string) bool {
	return strings.HasPrefix(raw, " ") || strings.HasPrefix(raw, "\t")
}

func deduplicateStrings(in []string) []string {
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
