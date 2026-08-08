package jsresolve

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func buildLockContext(ctx context.Context, root string, packages []jsresolution.PackageMetadata, limits resolverLimits) (lockContext, error) {
	if ctx == nil {
		return lockContext{}, fmt.Errorf("%w: context is required", shared.ErrValidation)
	}
	if strings.TrimSpace(root) == "" {
		return lockContext{}, fmt.Errorf("%w: repository root is required", shared.ErrValidation)
	}
	if err := ctx.Err(); err != nil {
		return lockContext{}, err
	}
	rootAbs, err := filepathAbsClean(root)
	if err != nil {
		return lockContext{}, fmt.Errorf("%w: resolve repository root: %v", shared.ErrValidation, err)
	}
	rootInfo, err := os.Lstat(rootAbs)
	if err != nil {
		return lockContext{}, fmt.Errorf("%w: repository root: %v", shared.ErrValidation, err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return lockContext{}, fmt.Errorf("%w: repository root must be a real directory", shared.ErrValidation)
	}
	rootDir, err := os.OpenRoot(rootAbs)
	if err != nil {
		return lockContext{}, fmt.Errorf("%w: open repository root: %v", shared.ErrValidation, err)
	}
	defer func() { _ = rootDir.Close() }()

	out := lockContext{bindings: map[string][]lockSelection{}}
	coverage := resolutionCoverageSink{limit: limits.maxCoverageIssues}
	manifests := map[string]packageRequests{}
	var rawLocks []rawLockFile
	entries, files := 0, 0
	manifestBindings, lockBindings := 0, 0
	bytesRead := int64(0)
	discoveryComplete := true

	walkErr := fs.WalkDir(rootDir.FS(), ".", func(rel string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			if rel == "." {
				return fmt.Errorf("walk repository root: %w", walkErr)
			}
			discoveryComplete = false
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnreadableMetadata, Path: rel, Detail: "lock/importer metadata entry could not be inspected"})
			return nil
		}
		entries++
		if entries > limits.maxLockEntries {
			discoveryComplete = false
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: ".", Detail: fmt.Sprintf("lock/importer filesystem entry budget exceeded (%d)", limits.maxLockEntries)})
			return fs.SkipAll
		}
		if entry.IsDir() {
			if rel != "." && skipMetadataDir(entry.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			target, statErr := rootDir.Stat(rel)
			if statErr != nil || target.IsDir() {
				discoveryComplete = false
				coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnreadableMetadata, Path: rel, Detail: "symlinked repository entry may hide nearer lock/importer metadata"})
				return nil
			}
		}
		if !isLockContextFile(entry.Name()) {
			return nil
		}
		manager, isLock := lockManagerForFile(entry.Name())
		if entry.Type()&os.ModeSymlink != 0 {
			if isLock {
				out.sources = append(out.sources, lockSourceContext{source: rel, dir: path.Dir(rel), manager: manager, uncertain: true})
			}
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnreadableMetadata, Path: rel, Detail: "lock/importer metadata is symlinked and was not followed"})
			return nil
		}
		if files >= limits.maxLockFiles {
			discoveryComplete = false
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: rel, Detail: fmt.Sprintf("lock/importer metadata file budget exceeded (%d)", limits.maxLockFiles)})
			return fs.SkipAll
		}
		info, infoErr := entry.Info()
		if infoErr != nil || !info.Mode().IsRegular() {
			if isLock {
				out.sources = append(out.sources, lockSourceContext{source: rel, dir: path.Dir(rel), manager: manager, uncertain: true})
			}
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnreadableMetadata, Path: rel, Detail: "lock/importer metadata entry is not a stable regular file"})
			return nil
		}
		remaining := limits.maxLockTotalBytes - bytesRead
		if remaining <= 0 || info.Size() > remaining {
			discoveryComplete = false
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: rel, Detail: fmt.Sprintf("aggregate lock/importer metadata byte budget exceeded (%d)", limits.maxLockTotalBytes)})
			return fs.SkipAll
		}
		files++
		content, readErr := readBoundedMetadata(rootDir, rel, info, limits.maxLockFileBytes, remaining)
		if readErr != nil {
			if isLock {
				out.sources = append(out.sources, lockSourceContext{source: rel, dir: path.Dir(rel), manager: manager, uncertain: true})
			}
			kind := jsresolution.CoverageUnreadableMetadata
			if errorsIsMetadataBudget(readErr) {
				kind = jsresolution.CoverageMetadataBudgetExceeded
			}
			coverage.add(jsresolution.CoverageIssue{Kind: kind, Path: rel, Detail: readErr.Error()})
			if errors.Is(readErr, errMetadataTotalBudget) {
				discoveryComplete = false
				return fs.SkipAll
			}
			return nil
		}
		bytesRead += int64(len(content))

		switch entry.Name() {
		case "package.json":
			manifest := parsePackageRequests(rel, content, limits)
			if len(manifest.dependencies) > limits.maxLockBindings-manifestBindings {
				manifest.uncertain = true
				manifest.dependencies = nil
				coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: rel, Detail: fmt.Sprintf("aggregate package dependency request budget exceeded (%d)", limits.maxLockBindings)})
			} else {
				manifestBindings += len(manifest.dependencies)
			}
			manifests[manifest.dir] = manifest
			if manifest.uncertain {
				coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMalformedMetadata, Path: rel, Detail: "package.json dependency metadata could not be parsed for lockfile correlation"})
			}
			if manager := packageManagerFamily(manifest.packageManager); manager == "unsupported" {
				coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedPackageManager, Path: rel, Detail: fmt.Sprintf("packageManager %q is outside npm/yarn/pnpm R2C support", boundedCoverageText(manifest.packageManager))})
			}
		case "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock":
			out.sources = append(out.sources, lockSourceContext{source: rel, dir: path.Dir(rel), manager: manager})
			rawLocks = append(rawLocks, rawLockFile{source: rel, dir: path.Dir(rel), manager: manager, content: content})
		case "bun.lock", "bun.lockb":
			out.sources = append(out.sources, lockSourceContext{source: rel, dir: path.Dir(rel), manager: "bun", uncertain: true})
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageUnsupportedPackageManager, Path: rel, Detail: "Bun lockfile correlation is not supported by R2C"})
		}
		return nil
	})
	if walkErr != nil {
		if err := ctx.Err(); err != nil {
			return lockContext{}, err
		}
		return lockContext{}, fmt.Errorf("inventory javascript lock metadata: %w", walkErr)
	}

	out.sources = normalizeLockSourcesForManagers(out.sources, manifests, &coverage)
	includedSources := make(map[string]struct{}, len(out.sources))
	for _, source := range out.sources {
		includedSources[source.source] = struct{}{}
	}
	workspaceByName := indexWorkspacesByName(packages)
	for _, raw := range rawLocks {
		if _, ok := includedSources[raw.source]; !ok {
			continue
		}
		if err := ctx.Err(); err != nil {
			return lockContext{}, err
		}
		var selections []lockSelection
		var issues []jsresolution.CoverageIssue
		var parseErr error
		switch raw.manager {
		case "npm":
			selections, issues, parseErr = parseNPMLockSelections(ctx, raw, limits)
		case "pnpm":
			selections, issues, parseErr = parsePNPMLockSelections(ctx, raw, workspaceByName, limits)
		case "yarn":
			selections, issues, parseErr = parseYarnLockSelections(ctx, raw, manifests, workspaceByName, limits)
		}
		coverage.addAll(issues)
		if parseErr != nil {
			markLockSourceUncertain(out.sources, raw.source)
			coverage.add(jsresolution.CoverageIssue{Kind: classifyLockParseCoverage(parseErr), Path: raw.source, Detail: boundedCoverageText(parseErr.Error())})
			continue
		}
		if len(selections) > limits.maxLockBindings-lockBindings {
			markLockSourceUncertain(out.sources, raw.source)
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: raw.source, Detail: fmt.Sprintf("aggregate lock selection budget exceeded (%d)", limits.maxLockBindings)})
			continue
		}
		lockBindings += len(selections)
		for _, selection := range selections {
			key := lockBindingKey(selection.source, selection.importer, selection.name)
			out.bindings[key] = append(out.bindings[key], selection)
		}
	}

	for key := range out.bindings {
		values := out.bindings[key]
		sort.Slice(values, func(i, j int) bool { return lockSelectionLess(values[i], values[j]) })
		out.bindings[key] = deduplicateLockSelections(values)
	}
	sort.Slice(out.sources, func(i, j int) bool {
		if out.sources[i].dir != out.sources[j].dir {
			return out.sources[i].dir < out.sources[j].dir
		}
		if out.sources[i].manager != out.sources[j].manager {
			return out.sources[i].manager < out.sources[j].manager
		}
		return out.sources[i].source < out.sources[j].source
	})
	out.sources = deduplicateLockSources(out.sources)
	if !discoveryComplete {
		for i := range out.sources {
			out.sources[i].uncertain = true
		}
		out.sources = append(out.sources, lockSourceContext{source: ".", dir: ".", manager: "unknown", uncertain: true})
		sort.Slice(out.sources, func(i, j int) bool {
			if out.sources[i].dir != out.sources[j].dir {
				return out.sources[i].dir < out.sources[j].dir
			}
			if out.sources[i].manager != out.sources[j].manager {
				return out.sources[i].manager < out.sources[j].manager
			}
			return out.sources[i].source < out.sources[j].source
		})
		out.sources = deduplicateLockSources(out.sources)
	}
	out.coverage = append(out.coverage, coverage.issues...)
	return out, nil
}

func buildCompleteLockContext(ctx context.Context, root string, packages []jsresolution.PackageMetadata, limits resolverLimits) (lockContext, error) {
	return buildLockContext(ctx, root, packages, limits)
}

func classifyLockParseCoverage(err error) jsresolution.CoverageIssueKind {
	if errors.Is(err, errUnsupportedPNPMImporterLayout) || errors.Is(err, errUnsupportedNPMLockLayout) {
		return jsresolution.CoverageUnsupportedMetadata
	}
	return jsresolution.CoverageMalformedMetadata
}
