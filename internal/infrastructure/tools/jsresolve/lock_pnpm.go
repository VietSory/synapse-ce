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
	importer  string
	name      string
	specifier string
	version   string
}

func parsePNPMLockSelections(ctx context.Context, raw rawLockFile, workspaces map[string][]jsresolution.PackageIdentity, limits resolverLimits) ([]lockSelection, []jsresolution.CoverageIssue, error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw.content))
	scanner.Buffer(make([]byte, 0, 64*1024), limits.maxLockLineBytes)
	inImporters := false
	currentImporter := ""
	currentGroup := ""
	var current *pnpmImporterDependency
	var records []pnpmImporterDependency
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
			if inImporters || strings.TrimSpace(rawLine) == "importers:" {
				return nil, nil, fmt.Errorf("pnpm-lock.yaml importers use tab indentation")
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
			if plain == "importers:" {
				inImporters = true
				currentImporter, currentGroup = "", ""
				continue
			}
			if inImporters {
				break
			}
			continue
		}
		if !inImporters {
			continue
		}

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
				currentGroup = key
			default:
				currentGroup = ""
			}
		case 6:
			flush()
			if currentImporter == "" || currentGroup == "" {
				continue
			}
			current = &pnpmImporterDependency{importer: currentImporter, name: key}
			if hasValue {
				current.version = value
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
				current.specifier = value
			case "version":
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
	}
	flush()
	if len(records) > limits.maxLockBindings {
		return nil, nil, fmt.Errorf("pnpm importer dependency count exceeds budget (%d)", limits.maxLockBindings)
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan pnpm-lock.yaml: %w", err)
	}
	if !inImporters {
		return nil, nil, fmt.Errorf("%w: pnpm-lock.yaml has no importers mapping", errUnsupportedPNPMImporterLayout)
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
		if peer := strings.IndexByte(version, '('); peer >= 0 {
			version = version[:peer]
		}
		version = strings.TrimSpace(version)
		if !sbom.IsResolvedVersion(version) {
			appendUnsupported(importer, name, fmt.Sprintf("pnpm dependency %q has unresolved version %q", name, boundedCoverageText(version)))
			continue
		}
		selections = append(selections, lockSelection{kind: lockSelectionExternal, manager: "pnpm", source: raw.source, importer: importer, name: name, version: version})
	}
	if len(selections) > limits.maxLockBindings {
		return nil, issues.issues, fmt.Errorf("pnpm selection budget exceeded (%d)", limits.maxLockBindings)
	}
	return selections, issues.issues, nil
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
