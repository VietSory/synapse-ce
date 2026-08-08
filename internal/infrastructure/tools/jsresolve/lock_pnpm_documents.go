package jsresolve

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// selectPNPMV9LockDocument supports pnpm's current multi-document lockfile
// shape without mixing environment metadata into the workspace lock. A file
// may contain environment documents whose lockfileVersion begins with env-,
// plus exactly one main wanted-lock document at version 9.0.
func selectPNPMV9LockDocument(content []byte, maxLineBytes int) ([]byte, error) {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	var current bytes.Buffer
	var selected []byte
	flush := func() error {
		doc := append([]byte(nil), current.Bytes()...)
		current.Reset()
		if len(bytes.TrimSpace(doc)) == 0 {
			return nil
		}
		version, err := pnpmDocumentLockfileVersion(doc, maxLineBytes)
		if err != nil {
			return err
		}
		switch {
		case version == "9.0":
			if selected != nil {
				return fmt.Errorf("pnpm-lock.yaml contains multiple v9 main lock documents")
			}
			selected = doc
		case strings.HasPrefix(version, "env-"):
			return nil
		default:
			return fmt.Errorf("%w: pnpm-lock.yaml document version %q is outside supported v9/env layouts", errUnsupportedPNPMImporterLayout, boundedCoverageText(version))
		}
		return nil
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "---" || line == "..." {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		current.WriteString(line)
		current.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan pnpm-lock.yaml documents: %w", err)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	if selected == nil {
		return nil, fmt.Errorf("%w: pnpm-lock.yaml has no v9 main lock document", errUnsupportedPNPMImporterLayout)
	}
	return selected, nil
}

func pnpmDocumentLockfileVersion(doc []byte, maxLineBytes int) (string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(doc))
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	seen := false
	version := ""
	for scanner.Scan() {
		rawLine := scanner.Text()
		if strings.ContainsRune(rawLine, '\t') {
			continue
		}
		plain := strings.TrimSpace(stripYAMLComment(rawLine))
		if plain == "" {
			continue
		}
		indent, _ := yamlIndent(rawLine)
		if indent != 0 {
			continue
		}
		key, value, hasValue, err := parseSimpleYAMLMapping(plain)
		if err != nil {
			return "", fmt.Errorf("pnpm-lock.yaml document metadata: %w", err)
		}
		if key != "lockfileVersion" {
			continue
		}
		if seen {
			return "", fmt.Errorf("pnpm-lock.yaml document repeats lockfileVersion")
		}
		seen = true
		if !hasValue || value == "" {
			return "", fmt.Errorf("pnpm-lock.yaml document has no scalar lockfileVersion")
		}
		version = value
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scan pnpm-lock.yaml document metadata: %w", err)
	}
	if !seen {
		return "", fmt.Errorf("pnpm-lock.yaml document has no lockfileVersion")
	}
	return version, nil
}
