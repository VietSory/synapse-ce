package manifest

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// parseGemfileLockEdges reconstructs the RubyGems dependency graph from a
// Gemfile.lock. Syft catalogs gems as a flat component list with no edges, so
// dependency paths are missing for Ruby; this rebuilds them from the lockfile's
// GEM > specs section, where each gem lists its direct dependencies indented
// beneath it. Edges are keyed by PURL (pkg:gem/<name>@<version>) to match Syft's
// component identities so they connect in the graph.
func parseGemfileLockEdges(data []byte) []sbom.Dependency {
	versions := map[string]string{} // gem name -> resolved version
	type spec struct {
		name string
		deps []string // dependency gem names
	}
	var specs []*spec
	var cur *spec

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	inSpecs := false
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		// Section transitions: a non-indented, non-empty line ends the GEM/specs block.
		if line != "" && !strings.HasPrefix(line, " ") {
			inSpecs = line == "GEM"
			cur = nil
			continue
		}
		if !inSpecs {
			continue
		}
		if trimmed == "specs:" {
			cur = nil
			continue
		}
		indent := countIndent(line)
		switch indent {
		case 4: // a gem spec: " name (version)"
			name, ver, ok := parseGemSpecLine(trimmed)
			if !ok {
				cur = nil
				continue
			}
			versions[name] = ver
			cur = &spec{name: name}
			specs = append(specs, cur)
		case 6: // a dependency of the current gem: " depname (constraint)"
			if cur == nil {
				continue
			}
			dep := depName(trimmed)
			if dep != "" {
				cur.deps = append(cur.deps, dep)
			}
		}
	}

	purl := func(name string) string {
		v := versions[name]
		if v == "" {
			return ""
		}
		return "pkg:gem/" + name + "@" + v
	}
	out := make([]sbom.Dependency, 0, len(specs))
	for _, s := range specs {
		ref := purl(s.name)
		if ref == "" {
			continue
		}
		seen := map[string]bool{ref: true}
		var on []string
		for _, d := range s.deps {
			if p := purl(d); p != "" && !seen[p] {
				seen[p] = true
				on = append(on, p)
			}
		}
		if len(on) > 0 {
			out = append(out, sbom.Dependency{Ref: ref, DependsOn: on})
		}
	}
	return out
}

func countIndent(line string) int {
	n := 0
	for _, r := range line {
		if r != ' ' {
			break
		}
		n++
	}
	return n
}

// parseGemSpecLine parses "name (1.2.3)" -> ("name","1.2.3",true). Lines with a
// version constraint (operators) are dependency lines, not spec lines.
func parseGemSpecLine(s string) (name, version string, ok bool) {
	open := strings.LastIndex(s, " (")
	if open < 0 || !strings.HasSuffix(s, ")") {
		return "", "", false
	}
	name = strings.TrimSpace(s[:open])
	version = strings.TrimSuffix(s[open+2:], ")")
	// A resolved spec version is a bare version (no constraint operators / commas).
	if name == "" || version == "" || strings.ContainsAny(version, "~><=,") {
		return "", "", false
	}
	return name, version, true
}

func depName(s string) string {
	if i := strings.Index(s, " ("); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if s == "" || strings.HasSuffix(s, ":") {
		return ""
	}
	return s
}
