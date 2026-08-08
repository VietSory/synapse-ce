package jsresolve

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

type npmLockPackage struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Link                 bool              `json:"link"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

type npmLockV1Dependency struct {
	Version string `json:"version"`
}

func parseNPMLockSelections(ctx context.Context, raw rawLockFile, limits resolverLimits) ([]lockSelection, []jsresolution.CoverageIssue, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := validateNoDuplicateJSONKeys(raw.content); err != nil {
		return nil, nil, fmt.Errorf("parse npm lock %q: %w", raw.source, err)
	}
	var lock struct {
		LockfileVersion int                            `json:"lockfileVersion"`
		Packages        map[string]npmLockPackage      `json:"packages"`
		Dependencies    map[string]npmLockV1Dependency `json:"dependencies"`
	}
	if err := json.Unmarshal(raw.content, &lock); err != nil {
		return nil, nil, fmt.Errorf("parse npm lock %q: %w", raw.source, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if len(lock.Packages) == 0 {
		if lock.LockfileVersion != 1 {
			return nil, nil, fmt.Errorf("%w: npm lockfileVersion %d has no supported packages map", errUnsupportedNPMLockLayout, lock.LockfileVersion)
		}
		return parseNPMLockV1Selections(ctx, raw, lock.Dependencies, limits)
	}
	if lock.LockfileVersion != 2 && lock.LockfileVersion != 3 {
		return nil, nil, fmt.Errorf("%w: npm lockfileVersion %d", errUnsupportedNPMLockLayout, lock.LockfileVersion)
	}
	if len(lock.Packages) > limits.maxLockEntries {
		return nil, nil, fmt.Errorf("npm lock packages exceed budget (%d)", limits.maxLockEntries)
	}

	paths := make([]string, 0, len(lock.Packages))
	for pkgPath := range lock.Packages {
		if len(pkgPath) > limits.maxModulePathBytes || repositorySegmentCount(pkgPath) > limits.maxModulePathSegments {
			return nil, nil, fmt.Errorf("npm lock package path exceeds resolver budget")
		}
		paths = append(paths, pkgPath)
	}
	sort.Strings(paths)
	var selections []lockSelection
	issues := resolutionCoverageSink{limit: limits.maxCoverageIssues}
	appendUnsupported := func(importer, name, detail string) {
		selections = append(selections, lockSelection{kind: lockSelectionUnsupported, manager: "npm", source: raw.source, importer: importer, name: name})
		issues.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedMetadata, Path: raw.source, Detail: detail})
	}
	for _, importerKey := range paths {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if importerKey != "" && containsNodeModulesPath(importerKey) {
			continue
		}
		importer, err := repositoryJoin(raw.dir, importerKey)
		if err != nil {
			issues.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedMetadata, Path: raw.source, Detail: fmt.Sprintf("npm lock importer %q escapes repository root", boundedCoverageText(importerKey))})
			continue
		}
		pkg := lock.Packages[importerKey]
		for _, rawName := range npmLockDependencyNames(pkg) {
			name, err := jsresolution.NormalizePackageName(rawName)
			if err != nil {
				issues.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedMetadata, Path: raw.source, Detail: fmt.Sprintf("npm lock dependency name %q is invalid", boundedCoverageText(rawName))})
				continue
			}
			targetPath := resolveNPMLockDep(importerKey, rawName, lock.Packages)
			if targetPath == "" {
				appendUnsupported(importer, name, fmt.Sprintf("npm lock dependency %q has no installed target in the packages map", name))
				continue
			}
			target := lock.Packages[targetPath]
			if target.Name != "" {
				targetName, nameErr := jsresolution.NormalizePackageName(target.Name)
				if nameErr != nil || targetName != name {
					appendUnsupported(importer, name, fmt.Sprintf("npm lock dependency %q resolves through an unsupported npm alias", name))
					continue
				}
			}
			if target.Link {
				workspacePath, joinErr := repositoryJoin(raw.dir, target.Resolved)
				if joinErr != nil || target.Resolved == "" {
					appendUnsupported(importer, name, fmt.Sprintf("npm lock link for %q has unsafe target %q", name, boundedCoverageText(target.Resolved)))
					continue
				}
				selections = append(selections, lockSelection{kind: lockSelectionWorkspace, manager: "npm", source: raw.source, importer: importer, name: name, workspacePath: workspacePath})
				if len(selections) > limits.maxLockBindings {
					return nil, issues.issues, fmt.Errorf("npm lock selection budget exceeded (%d)", limits.maxLockBindings)
				}
				continue
			}
			version := strings.TrimSpace(target.Version)
			if !sbom.IsResolvedVersion(version) {
				appendUnsupported(importer, name, fmt.Sprintf("npm lock dependency %q has unresolved version %q", name, boundedCoverageText(version)))
				continue
			}
			selections = append(selections, lockSelection{kind: lockSelectionExternal, manager: "npm", source: raw.source, importer: importer, name: name, version: version})
			if len(selections) > limits.maxLockBindings {
				return nil, issues.issues, fmt.Errorf("npm lock selection budget exceeded (%d)", limits.maxLockBindings)
			}
		}
	}
	return selections, issues.issues, nil
}

func parseNPMLockV1Selections(ctx context.Context, raw rawLockFile, deps map[string]npmLockV1Dependency, limits resolverLimits) ([]lockSelection, []jsresolution.CoverageIssue, error) {
	if len(deps) > limits.maxLockBindings {
		return nil, nil, fmt.Errorf("npm lock v1 dependency count exceeds budget (%d)", limits.maxLockBindings)
	}
	var names []string
	for name := range deps {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []lockSelection
	issues := resolutionCoverageSink{limit: limits.maxCoverageIssues}
	for _, rawName := range names {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		name, err := jsresolution.NormalizePackageName(rawName)
		if err != nil {
			issues.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedMetadata, Path: raw.source, Detail: fmt.Sprintf("npm lock dependency name %q is invalid", boundedCoverageText(rawName))})
			continue
		}
		version := strings.TrimSpace(deps[rawName].Version)
		if !sbom.IsResolvedVersion(version) {
			out = append(out, lockSelection{kind: lockSelectionUnsupported, manager: "npm", source: raw.source, importer: raw.dir, name: name})
			issues.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedMetadata, Path: raw.source, Detail: fmt.Sprintf("npm lock v1 dependency %q has unresolved version %q", name, boundedCoverageText(version))})
			continue
		}
		out = append(out, lockSelection{kind: lockSelectionExternal, manager: "npm", source: raw.source, importer: raw.dir, name: name, version: version})
	}
	return out, issues.issues, nil
}

func npmLockDependencyNames(pkg npmLockPackage) []string {
	set := map[string]struct{}{}
	for _, values := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies} {
		for name := range values {
			set[name] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func resolveNPMLockDep(fromPath, depName string, packages map[string]npmLockPackage) string {
	cur := fromPath
	for {
		candidate := "node_modules/" + depName
		if cur != "" {
			candidate = cur + "/node_modules/" + depName
		}
		if _, ok := packages[candidate]; ok {
			return candidate
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

func containsNodeModulesPath(value string) bool {
	if value == "node_modules" || strings.HasPrefix(value, "node_modules/") {
		return true
	}
	return strings.Contains(value, "/node_modules/")
}

func repositoryJoin(base, declared string) (string, error) {
	if declared == "" || declared == "." {
		if base == "" {
			return ".", nil
		}
		return jsresolution.NormalizeRepositoryLocation(base)
	}
	if strings.HasPrefix(declared, "/") || hasDeclaredWindowsVolume(declared) {
		return "", fmt.Errorf("absolute path")
	}
	joined := path.Clean(path.Join(base, strings.ReplaceAll(declared, "\\", "/")))
	if joined == ".." || strings.HasPrefix(joined, "../") {
		return "", fmt.Errorf("path escapes repository root")
	}
	return jsresolution.NormalizeRepositoryLocation(joined)
}
