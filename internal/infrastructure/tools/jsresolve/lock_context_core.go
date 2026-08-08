package jsresolve

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

const manifestGuardPrefix = "manifest-guard:"

type lockSelectionKind uint8

const (
	lockSelectionExternal lockSelectionKind = iota + 1
	lockSelectionWorkspace
)

type lockSelection struct {
	kind          lockSelectionKind
	manager       string
	source        string
	importer      string
	name          string
	version       string
	workspacePath string
}

type lockSourceContext struct {
	source    string
	dir       string
	manager   string
	uncertain bool
}

type lockContext struct {
	sources  []lockSourceContext
	bindings map[string][]lockSelection
	coverage []jsresolution.CoverageIssue
}

type packageRequests struct {
	source         string
	dir            string
	packageManager string
	dependencies   map[string]string
	uncertain      bool
}

type rawLockFile struct {
	source  string
	dir     string
	manager string
	content []byte
}

func isLockContextFile(name string) bool {
	switch name {
	case "package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb":
		return true
	default:
		return false
	}
}

func lockManagerForFile(name string) (string, bool) {
	switch name {
	case "package-lock.json", "npm-shrinkwrap.json":
		return "npm", true
	case "pnpm-lock.yaml":
		return "pnpm", true
	case "yarn.lock":
		return "yarn", true
	default:
		return "", false
	}
}

func parsePackageRequests(source string, content []byte, limits resolverLimits) packageRequests {
	out := packageRequests{source: source, dir: path.Dir(source), dependencies: map[string]string{}}
	var manifest struct {
		PackageManager       string            `json:"packageManager"`
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(content, &manifest); err != nil {
		out.uncertain = true
		return out
	}
	out.packageManager = strings.TrimSpace(manifest.PackageManager)
	for _, values := range []map[string]string{manifest.Dependencies, manifest.DevDependencies, manifest.OptionalDependencies} {
		for rawName, request := range values {
			if len(out.dependencies) >= limits.maxLockBindings {
				out.uncertain = true
				return out
			}
			name, err := jsresolution.NormalizePackageName(rawName)
			if err != nil || len(request) > limits.maxSpecifierBytes {
				out.uncertain = true
				continue
			}
			if previous, ok := out.dependencies[name]; ok && previous != request {
				out.uncertain = true
				continue
			}
			out.dependencies[name] = request
		}
	}
	return out
}

func packageManagerFamily(value string) string {
	if value == "" {
		return ""
	}
	name := value
	if at := strings.IndexByte(name, '@'); at > 0 {
		name = name[:at]
	}
	switch strings.ToLower(name) {
	case "npm", "yarn", "pnpm":
		return strings.ToLower(name)
	case "bun":
		return "unsupported"
	default:
		return "unsupported"
	}
}

func npmPackageManagerMajor(value string) (int, bool) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(strings.ToLower(value), "npm@") {
		return 0, false
	}
	version := strings.TrimSpace(value[len("npm@"):])
	if version == "" {
		return 0, false
	}
	if i := strings.IndexAny(version, ".-+"); i >= 0 {
		version = version[:i]
	}
	major, err := strconv.Atoi(version)
	if err != nil || major <= 0 {
		return 0, false
	}
	return major, true
}

func normalizeLockSourcesForManagers(sources []lockSourceContext, manifests map[string]packageRequests, coverage *resolutionCoverageSink) []lockSourceContext {
	byDir := map[string][]lockSourceContext{}
	for _, source := range sources {
		byDir[source.dir] = append(byDir[source.dir], source)
	}
	dirSet := make(map[string]struct{}, len(byDir)+len(manifests))
	for dir := range byDir {
		dirSet[dir] = struct{}{}
	}
	for dir := range manifests {
		dirSet[dir] = struct{}{}
	}
	dirs := make([]string, 0, len(dirSet))
	for dir := range dirSet {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)

	var out []lockSourceContext
	for _, dir := range dirs {
		values := byDir[dir]
		manifest, hasManifest := manifests[dir]
		values = applyNPMLockPrecedence(values, manifest, hasManifest, coverage)
		guards := manifestGuardSources(manifest, hasManifest)

		preferred := ""
		if hasManifest && !manifest.uncertain {
			family := packageManagerFamily(manifest.packageManager)
			if family == "npm" || family == "yarn" || family == "pnpm" {
				preferred = family
			} else if family == "unsupported" {
				for i := range values {
					values[i].uncertain = true
				}
			}
		}
		if preferred != "" {
			matched := false
			selected := make([]lockSourceContext, 0, len(values))
			for _, source := range values {
				if source.manager == preferred {
					selected = append(selected, source)
					matched = true
				}
			}
			if matched {
				out = append(out, selected...)
				out = append(out, guards...)
				continue
			}
			coverage.add(jsresolution.CoverageIssue{
				Kind:   jsresolution.CoverageUnsupportedPackageManager,
				Path:   dir,
				Detail: fmt.Sprintf("packageManager selects %s but no matching lockfile was observed", preferred),
			})
			for i := range values {
				values[i].uncertain = true
			}
		}

		managers := map[string]struct{}{}
		for _, source := range values {
			if !strings.HasPrefix(source.manager, manifestGuardPrefix) {
				managers[source.manager] = struct{}{}
			}
		}
		if len(managers) > 1 {
			coverage.add(jsresolution.CoverageIssue{
				Kind:   jsresolution.CoverageUnsupportedPackageManager,
				Path:   dir,
				Detail: "multiple package-manager lockfiles share one scope without a unique packageManager declaration",
			})
			for i := range values {
				values[i].uncertain = true
			}
		}
		out = append(out, values...)
		out = append(out, guards...)
	}
	return out
}

func manifestGuardSources(manifest packageRequests, present bool) []lockSourceContext {
	if !present {
		return nil
	}
	if manifest.uncertain || packageManagerFamily(manifest.packageManager) == "unsupported" {
		return []lockSourceContext{{source: manifest.source, dir: manifest.dir, manager: manifestGuardPrefix + "*"}}
	}
	var names []string
	for name, request := range manifest.dependencies {
		if manifestRequestNeedsLockEvidence(name, request) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	out := make([]lockSourceContext, 0, len(names))
	for _, name := range names {
		out = append(out, lockSourceContext{source: manifest.source, dir: manifest.dir, manager: manifestGuardPrefix + name})
	}
	return out
}

func manifestRequestNeedsLockEvidence(name, request string) bool {
	request = strings.TrimSpace(request)
	if request == "" {
		return true
	}
	if strings.HasPrefix(request, "npm:") {
		target := strings.TrimPrefix(request, "npm:")
		targetName := packageAliasTargetName(target)
		if targetName == "" {
			return false // npm:<range> keeps the dependency key's identity
		}
		normalized, err := jsresolution.NormalizePackageName(targetName)
		return err != nil || normalized != name
	}
	lower := strings.ToLower(request)
	for _, prefix := range []string{"workspace:", "file:", "link:", "portal:", "patch:", "git:", "git+", "github:", "http:", "https:", "ssh:", "catalog:", "catalogs:"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return strings.HasPrefix(request, "./") || strings.HasPrefix(request, "../") || strings.HasPrefix(request, "/") || strings.Contains(request, "/")
}

func packageAliasTargetName(target string) string {
	target = strings.TrimSpace(target)
	if target == "" || sbom.IsResolvedVersion(target) {
		return ""
	}
	if normalized, err := jsresolution.NormalizePackageName(target); err == nil {
		return normalized
	}
	if target[0] == '@' {
		for i := 1; i < len(target); i++ {
			if target[i] == '@' {
				return target[:i]
			}
		}
		return ""
	}
	if at := strings.IndexByte(target, '@'); at > 0 {
		return target[:at]
	}
	return ""
}

func applyNPMLockPrecedence(values []lockSourceContext, manifest packageRequests, hasManifest bool, coverage *resolutionCoverageSink) []lockSourceContext {
	shrinkwrap := -1
	packageLock := -1
	for i := range values {
		switch path.Base(values[i].source) {
		case "npm-shrinkwrap.json":
			shrinkwrap = i
		case "package-lock.json":
			packageLock = i
		}
	}
	if shrinkwrap < 0 {
		return values
	}
	family := ""
	if hasManifest && !manifest.uncertain {
		family = packageManagerFamily(manifest.packageManager)
	}
	if family != "" && family != "npm" {
		return values
	}
	major, known := npmPackageManagerMajor(manifest.packageManager)
	if known && major >= 12 {
		return removeLockSourceAt(values, shrinkwrap)
	}
	if known && major <= 11 {
		if packageLock >= 0 {
			return removeLockSourceAt(values, packageLock)
		}
		return values
	}

	coverage.add(jsresolution.CoverageIssue{
		Kind:   jsresolution.CoverageUnsupportedPackageManager,
		Path:   manifestOrDir(manifest, values[shrinkwrap].dir),
		Detail: "npm-shrinkwrap.json semantics depend on npm major version; declare an exact npm packageManager version to correlate it safely",
	})
	for i := range values {
		if values[i].manager == "npm" {
			values[i].uncertain = true
		}
	}
	return values
}

func manifestOrDir(manifest packageRequests, dir string) string {
	if manifest.source != "" {
		return manifest.source
	}
	return dir
}

func removeLockSourceAt(values []lockSourceContext, index int) []lockSourceContext {
	if index < 0 || index >= len(values) {
		return values
	}
	out := make([]lockSourceContext, 0, len(values)-1)
	out = append(out, values[:index]...)
	out = append(out, values[index+1:]...)
	return out
}

func markLockSourceUncertain(sources []lockSourceContext, source string) {
	for i := range sources {
		if sources[i].source == source {
			sources[i].uncertain = true
		}
	}
}

func lockSourcesAtDir(sources []lockSourceContext, dir string) []lockSourceContext {
	start := sort.Search(len(sources), func(i int) bool { return sources[i].dir >= dir })
	var out []lockSourceContext
	for i := start; i < len(sources) && sources[i].dir == dir; i++ {
		out = append(out, sources[i])
	}
	return out
}

func lockBindingKey(source, importer, name string) string {
	return source + "\x00" + importer + "\x00" + name
}

func lockSelectionLess(a, b lockSelection) bool {
	if a.kind != b.kind {
		return a.kind < b.kind
	}
	if a.name != b.name {
		return a.name < b.name
	}
	if a.version != b.version {
		return a.version < b.version
	}
	if a.workspacePath != b.workspacePath {
		return a.workspacePath < b.workspacePath
	}
	if a.manager != b.manager {
		return a.manager < b.manager
	}
	if a.source != b.source {
		return a.source < b.source
	}
	return a.importer < b.importer
}

func deduplicateLockSelections(in []lockSelection) []lockSelection {
	if len(in) < 2 {
		return in
	}
	out := in[:1]
	for _, value := range in[1:] {
		last := out[len(out)-1]
		if value.kind == last.kind && value.name == last.name && value.version == last.version && value.workspacePath == last.workspacePath {
			continue
		}
		out = append(out, value)
	}
	return out
}

func deduplicateLockSources(in []lockSourceContext) []lockSourceContext {
	if len(in) < 2 {
		return in
	}
	out := in[:1]
	for _, value := range in[1:] {
		last := out[len(out)-1]
		if value.source == last.source && value.dir == last.dir && value.manager == last.manager {
			out[len(out)-1].uncertain = out[len(out)-1].uncertain || value.uncertain
			continue
		}
		out = append(out, value)
	}
	return out
}
