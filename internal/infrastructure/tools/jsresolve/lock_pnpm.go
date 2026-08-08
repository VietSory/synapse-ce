package jsresolve

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

var errUnsupportedPNPMImporterLayout = errors.New("unsupported pnpm importer layout")

type pnpmImporterDependency struct {
	importer      string
	name          string
	specifier     string
	version       string
	specifierSeen bool
	versionSeen   bool
}

func parsePNPMLockSelections(ctx context.Context, raw rawLockFile, workspaces map[string][]jsresolution.PackageIdentity, limits resolverLimits) ([]lockSelection, []jsresolution.CoverageIssue, error) {
	selectedContent, err := selectPNPMV9LockDocument(raw.content, limits.maxLockLineBytes)
	if err != nil {
		return nil, nil, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(selectedContent))
	scanner.Buffer(make([]byte, 0, 64*1024), limits.maxLockLineBytes)
	section := ""
	lockfileVersion := ""
	seenImporters := false
	seenPackages := false
	seenSnapshots := false
	currentImporter := ""
	currentGroup := ""
	var current *pnpmImporterDependency
	var records []pnpmImporterDependency
	packageIdentities := map[string]struct{}{}
	snapshotIdentities := map[string]struct{}{}
	packageEntries := 0
	snapshotEntries := 0
	topSeen := map[string]struct{}{}
	importerSeen := map[string]struct{}{}
	groupSeen := map[string]struct{}{}
	dependencySeen := map[string]struct{}{}
	packageSeen := map[string]struct{}{}
	snapshotSeen := map[string]struct{}{}
	flush := func() {
		if current != nil {
			records = append(records, *current)
			current = nil
		}
	}

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		rawLine := scanner.Text()
		if strings.ContainsRune(rawLine, '\t') {
			plain := strings.TrimSpace(rawLine)
			if section == "importers" || section == "packages" || section == "snapshots" || plain == "importers:" || plain == "packages:" || plain == "snapshots:" {
				return nil, nil, fmt.Errorf("pnpm-lock.yaml uses tab indentation in a correlated section")
			}
			continue
		}
		plain := strings.TrimSpace(stripYAMLComment(rawLine))
		if plain == "" {
			continue
		}
		indent, _ := yamlIndent(rawLine)
		if indent == 0 {
			flush()
			currentImporter, currentGroup = "", ""
			key, value, hasValue, err := parseSimpleYAMLMapping(plain)
			if err != nil {
				return nil, nil, fmt.Errorf("pnpm-lock.yaml top-level metadata: %w", err)
			}
			switch key {
			case "lockfileVersion", "importers", "packages", "snapshots":
				if _, duplicate := topSeen[key]; duplicate {
					return nil, nil, fmt.Errorf("pnpm-lock.yaml repeats top-level key %q", key)
				}
				topSeen[key] = struct{}{}
			}
			switch key {
			case "lockfileVersion":
				if !hasValue || value == "" {
					return nil, nil, fmt.Errorf("%w: pnpm-lock.yaml has no scalar lockfileVersion", errUnsupportedPNPMImporterLayout)
				}
				lockfileVersion = value
				section = ""
			case "importers":
				if hasValue {
					return nil, nil, fmt.Errorf("%w: pnpm-lock.yaml importers must be a mapping", errUnsupportedPNPMImporterLayout)
				}
				seenImporters = true
				section = "importers"
			case "packages":
				if hasValue {
					return nil, nil, fmt.Errorf("%w: pnpm-lock.yaml packages must be a mapping", errUnsupportedPNPMImporterLayout)
				}
				seenPackages = true
				section = "packages"
			case "snapshots":
				if hasValue {
					return nil, nil, fmt.Errorf("%w: pnpm-lock.yaml snapshots must be a mapping", errUnsupportedPNPMImporterLayout)
				}
				seenSnapshots = true
				section = "snapshots"
			default:
				section = ""
			}
			continue
		}

		switch section {
		case "importers":
			key, value, hasValue, err := parseSimpleYAMLMapping(plain)
			if err != nil {
				return nil, nil, fmt.Errorf("pnpm-lock.yaml importers: %w", err)
			}
			switch indent {
			case 2:
				flush()
				if hasValue {
					return nil, nil, fmt.Errorf("pnpm-lock.yaml importer %q must be a mapping", key)
				}
				if _, duplicate := importerSeen[key]; duplicate {
					return nil, nil, fmt.Errorf("pnpm-lock.yaml repeats importer %q", boundedCoverageText(key))
				}
				importerSeen[key] = struct{}{}
				currentImporter = key
				currentGroup = ""
			case 4:
				flush()
				if currentImporter == "" {
					return nil, nil, fmt.Errorf("pnpm-lock.yaml dependency group has no importer")
				}
				if hasValue {
					currentGroup = ""
					continue
				}
				switch key {
				case "dependencies", "devDependencies", "optionalDependencies":
					groupKey := currentImporter + "\x00" + key
					if _, duplicate := groupSeen[groupKey]; duplicate {
						return nil, nil, fmt.Errorf("pnpm-lock.yaml importer %q repeats dependency group %q", boundedCoverageText(currentImporter), key)
					}
					groupSeen[groupKey] = struct{}{}
					currentGroup = key
				default:
					currentGroup = ""
				}
			case 6:
				flush()
				if currentImporter == "" || currentGroup == "" {
					continue
				}
				dependencyKey := currentImporter + "\x00" + currentGroup + "\x00" + key
				if _, duplicate := dependencySeen[dependencyKey]; duplicate {
					return nil, nil, fmt.Errorf("pnpm-lock.yaml importer %q repeats dependency %q in %s", boundedCoverageText(currentImporter), boundedCoverageText(key), currentGroup)
				}
				dependencySeen[dependencyKey] = struct{}{}
				current = &pnpmImporterDependency{importer: currentImporter, name: key}
				if hasValue {
					current.version = value
					current.versionSeen = true
					flush()
				}
			case 8:
				if current == nil {
					continue
				}
				if !hasValue {
					return nil, nil, fmt.Errorf("pnpm-lock.yaml dependency field %q must be scalar", key)
				}
				switch key {
				case "specifier":
					if current.specifierSeen {
						return nil, nil, fmt.Errorf("pnpm-lock.yaml dependency %q repeats specifier", boundedCoverageText(current.name))
					}
					current.specifierSeen = true
					current.specifier = value
				case "version":
					if current.versionSeen {
						return nil, nil, fmt.Errorf("pnpm-lock.yaml dependency %q repeats version", boundedCoverageText(current.name))
					}
					current.versionSeen = true
					current.version = value
				}
			default:
				if indent < 6 {
					flush()
				}
			}
			if len(records) > limits.maxLockBindings {
				return nil, nil, fmt.Errorf("pnpm importer dependency count exceeds budget (%d)", limits.maxLockBindings)
			}
		case "packages":
			if indent != 2 {
				continue
			}
			key, _, hasValue, err := parseSimpleYAMLMapping(plain)
			if err != nil {
				return nil, nil, fmt.Errorf("pnpm-lock.yaml packages: %w", err)
			}
			if hasValue {
				return nil, nil, fmt.Errorf("pnpm-lock.yaml package %q must be a mapping", boundedCoverageText(key))
			}
			if _, duplicate := packageSeen[key]; duplicate {
				return nil, nil, fmt.Errorf("pnpm-lock.yaml repeats package %q", boundedCoverageText(key))
			}
			packageSeen[key] = struct{}{}
			packageEntries++
			if packageEntries > limits.maxLockEntries {
				return nil, nil, fmt.Errorf("pnpm package entry count exceeds budget (%d)", limits.maxLockEntries)
			}
			if name, version, ok := pnpmV9PackageIdentity(key); ok {
				packageIdentities[pnpmPackageIdentityKey(name, version)] = struct{}{}
			}
		case "snapshots":
			if indent != 2 {
				continue
			}
			key, err := parseSimpleYAMLMappingKey(plain)
			if err != nil {
				return nil, nil, fmt.Errorf("pnpm-lock.yaml snapshots: %w", err)
			}
			if _, duplicate := snapshotSeen[key]; duplicate {
				return nil, nil, fmt.Errorf("pnpm-lock.yaml repeats snapshot %q", boundedCoverageText(key))
			}
			snapshotSeen[key] = struct{}{}
			snapshotEntries++
			if snapshotEntries > limits.maxLockEntries {
				return nil, nil, fmt.Errorf("pnpm snapshot entry count exceeds budget (%d)", limits.maxLockEntries)
			}
			if name, version, ok := pnpmV9PackageIdentity(key); ok {
				snapshotIdentities[pnpmPackageIdentityKey(name, version)] = struct{}{}
			}
		}
	}
	flush()
	if len(records) > limits.maxLockBindings {
		return nil, nil, fmt.Errorf("pnpm importer dependency count exceeds budget (%d)", limits.maxLockBindings)
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan pnpm-lock.yaml: %w", err)
	}
	if !seenImporters {
		return nil, nil, fmt.Errorf("%w: pnpm-lock.yaml has no importers mapping", errUnsupportedPNPMImporterLayout)
	}
	if lockfileVersion != "9.0" {
		return nil, nil, fmt.Errorf("%w: pnpm-lock.yaml lockfileVersion %q is outside supported wanted-lock format 9.0", errUnsupportedPNPMImporterLayout, boundedCoverageText(lockfileVersion))
	}

	var selections []lockSelection
	issues := resolutionCoverageSink{limit: limits.maxCoverageIssues}
	appendUnsupported := func(importer, name, detail string) {
		selections = append(selections, lockSelection{kind: lockSelectionUnsupported, manager: "pnpm", source: raw.source, importer: importer, name: name})
		issues.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedMetadata, Path: raw.source, Detail: detail})
	}
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		name, err := jsresolution.NormalizePackageName(record.name)
		if err != nil {
			issues.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedMetadata, Path: raw.source, Detail: fmt.Sprintf("pnpm importer dependency name %q is invalid", boundedCoverageText(record.name))})
			continue
		}
		importer, err := repositoryJoin(raw.dir, record.importer)
		if err != nil {
			issues.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedMetadata, Path: raw.source, Detail: fmt.Sprintf("pnpm importer %q escapes repository root", boundedCoverageText(record.importer))})
			continue
		}
		version := strings.TrimSpace(record.version)
		if version == "" {
			appendUnsupported(importer, name, fmt.Sprintf("pnpm importer dependency %q has no resolved version", name))
			continue
		}
		if strings.HasPrefix(version, "link:") {
			workspacePath, joinErr := repositoryJoin(importer, strings.TrimPrefix(version, "link:"))
			if joinErr != nil || !workspaceIdentityAtPath(workspaces[name], workspacePath) {
				appendUnsupported(importer, name, fmt.Sprintf("pnpm link for %q does not identify an observed workspace", name))
				continue
			}
			selections = append(selections, lockSelection{kind: lockSelectionWorkspace, manager: "pnpm", source: raw.source, importer: importer, name: name, workspacePath: workspacePath})
			continue
		}
		if strings.HasPrefix(record.specifier, "workspace:") {
			appendUnsupported(importer, name, fmt.Sprintf("pnpm workspace request for %q is not represented by a link target", name))
			continue
		}
		if strings.Contains(version, ":") || strings.HasPrefix(version, "/") {
			appendUnsupported(importer, name, fmt.Sprintf("pnpm dependency %q uses unsupported resolved selector %q", name, boundedCoverageText(version)))
			continue
		}
		baseVersion, ok := pnpmV9ResolvedBaseVersion(version)
		if !ok {
			appendUnsupported(importer, name, fmt.Sprintf("pnpm dependency %q has malformed or unresolved version %q", name, boundedCoverageText(version)))
			continue
		}
		version = baseVersion
		identityKey := pnpmPackageIdentityKey(name, version)
		if !seenPackages {
			appendUnsupported(importer, name, fmt.Sprintf("pnpm v9 importer dependency %q has no packages mapping to verify resolved identity", name))
			continue
		}
		if _, ok := packageIdentities[identityKey]; !ok {
			appendUnsupported(importer, name, fmt.Sprintf("pnpm importer dependency %q resolves to %q but packages has no matching package identity", name, boundedCoverageText(version)))
			continue
		}
		if !seenSnapshots {
			appendUnsupported(importer, name, fmt.Sprintf("pnpm v9 importer dependency %q has no snapshots mapping to verify resolved instance", name))
			continue
		}
		if _, ok := snapshotIdentities[identityKey]; !ok {
			appendUnsupported(importer, name, fmt.Sprintf("pnpm importer dependency %q resolves to %q but snapshots has no matching package instance", name, boundedCoverageText(version)))
			continue
		}
		selections = append(selections, lockSelection{kind: lockSelectionExternal, manager: "pnpm", source: raw.source, importer: importer, name: name, version: version})
	}
	if len(selections) > limits.maxLockBindings {
		return nil, issues.issues, fmt.Errorf("pnpm selection budget exceeded (%d)", limits.maxLockBindings)
	}
	return selections, issues.issues, nil
}

func pnpmV9PackageIdentity(key string) (string, string, bool) {
	key = strings.TrimSpace(key)
	baseKey := key
	if peer := strings.IndexByte(baseKey, '('); peer >= 0 {
		if !pnpmV9ValidPeerSuffix(baseKey[peer:]) {
			return "", "", false
		}
		baseKey = strings.TrimSpace(baseKey[:peer])
	} else if strings.ContainsRune(baseKey, ')') {
		return "", "", false
	}
	separator := strings.LastIndexByte(baseKey, '@')
	if separator <= 0 || separator == len(baseKey)-1 {
		return "", "", false
	}
	name, err := jsresolution.NormalizePackageName(baseKey[:separator])
	if err != nil {
		return "", "", false
	}
	version, ok := pnpmV9ResolvedBaseVersion(baseKey[separator+1:])
	if !ok {
		return "", "", false
	}
	return name, version, true
}

func pnpmV9ResolvedBaseVersion(value string) (string, bool) {
	value = strings.TrimSpace(value)
	base := value
	if peer := strings.IndexByte(base, '('); peer >= 0 {
		if !pnpmV9ValidPeerSuffix(base[peer:]) {
			return "", false
		}
		base = strings.TrimSpace(base[:peer])
	} else if strings.ContainsRune(base, ')') {
		return "", false
	}
	if !sbom.IsResolvedVersion(base) {
		return "", false
	}
	return base, true
}

func pnpmV9ValidPeerSuffix(suffix string) bool {
	if suffix == "" || suffix[0] != '(' {
		return false
	}
	depth := 0
	groupHasContent := false
	for _, r := range suffix {
		switch r {
		case '(':
			if depth == 0 {
				groupHasContent = false
			}
			depth++
		case ')':
			if depth <= 0 || !groupHasContent {
				return false
			}
			depth--
		default:
			if depth == 0 {
				return false
			}
			if !strings.ContainsRune(" \t\r\n", r) {
				groupHasContent = true
			}
		}
	}
	return depth == 0
}

func pnpmPackageIdentityKey(name, version string) string {
	return name + "\x00" + version
}

func parseSimpleYAMLMapping(line string) (key, value string, hasValue bool, err error) {
	colon := yamlMappingColon(line)
	if colon <= 0 {
		return "", "", false, fmt.Errorf("expected a simple mapping entry")
	}
	rawKey := strings.TrimSpace(line[:colon])
	rawValue := strings.TrimSpace(line[colon+1:])
	if rawKey == "" || hasUnsupportedYAMLScalarSyntax(rawKey) {
		return "", "", false, fmt.Errorf("unsupported YAML mapping key")
	}
	key, err = unquoteYAMLScalar(rawKey)
	if err != nil || key == "" {
		return "", "", false, fmt.Errorf("invalid YAML mapping key")
	}
	if rawValue == "" {
		return key, "", false, nil
	}
	if hasUnsupportedYAMLScalarSyntax(rawValue) {
		return "", "", false, fmt.Errorf("unsupported YAML scalar value")
	}
	value, err = unquoteYAMLScalar(rawValue)
	if err != nil {
		return "", "", false, fmt.Errorf("invalid YAML scalar value")
	}
	return key, value, true, nil
}

func parseSimpleYAMLMappingKey(line string) (string, error) {
	colon := yamlMappingColon(line)
	if colon <= 0 {
		return "", fmt.Errorf("expected a mapping entry")
	}
	rawKey := strings.TrimSpace(line[:colon])
	if rawKey == "" || hasUnsupportedYAMLScalarSyntax(rawKey) {
		return "", fmt.Errorf("unsupported YAML mapping key")
	}
	key, err := unquoteYAMLScalar(rawKey)
	if err != nil || key == "" {
		return "", fmt.Errorf("invalid YAML mapping key")
	}
	return key, nil
}

func yamlMappingColon(line string) int {
	inSingle, inDouble := false, false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case ':':
			if !inSingle && !inDouble {
				return i
			}
		}
	}
	return -1
}

func workspaceIdentityAtPath(candidates []jsresolution.PackageIdentity, target string) bool {
	for _, candidate := range candidates {
		if candidate.Workspace && candidate.Path == target {
			return true
		}
	}
	return false
}
