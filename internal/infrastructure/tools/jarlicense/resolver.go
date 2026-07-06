// Package jarlicense recovers component licenses from the license TEXT embedded in
// JARs in the prepared workspace, for components the registry lookup left unknown.
// Java artifacts ship their license inside the JAR (META-INF/LICENSE, LICENSE.txt,
// …); this reads that text and classifies it with github.com/google/licensecheck —
// the standard Go license classifier — into an SPDX id, so a package whose registry
// metadata is missing (or returns "non-standard") still gets a real license.
//
// It is the deterministic, OFFLINE complement to the deps.dev enricher: no
// network, read-only, bounded. A JAR's own pom.properties supplies the
// authoritative coordinate (artifactId@version) used to match the component, so a
// mis-derived groupId in the SBOM does not break the match.
package jarlicense

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/licensetext"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxJARs          = 20000    // bound the workspace walk (workspace size is capped upstream)
	maxNestedBytes   = 96 << 20 // read a nested JAR into memory only if under this size
	maxEntriesPerJAR = 100000   // bound entries scanned per archive
	maxLicenseBytes  = 1 << 20  // a LICENSE file is small; cap the read defensively
	maxPropsBytes    = 1 << 20
	maxPomBytes      = 1 << 20 // an embedded pom.xml is small; cap the read defensively
)

// Resolver fills missing component licenses from JAR-embedded license text.
type Resolver struct{}

// New returns a resolver.
func New() *Resolver { return &Resolver{} }

var _ ports.LicenseFileResolver = (*Resolver)(nil)

// Resolve scans JARs under wsDir and fixes component licenses two ways, matching a JAR by
// artifact@version:
//
// OVERRIDE the DECLARED license. A JAR's own META-INF/maven/.../pom.xml <licenses> is the
// authoritative legal declaration (the same source Trivy uses). Syft, by contrast, CONCLUDES
// licenses by classifying every license text it finds inside the archive — for a JAR that bundles
// third-party notices (e.g. mysql-connector-java) that yields a spray of ~10 spurious SPDX ids.
// When we recover a declared license and the component's current set is empty OR has ≥2 entries
// (the spray), we replace it with the declared set. A single existing license is left alone
// (nothing to disambiguate, and the declared name is not always more precise).
// FILL a still-missing license from embedded license TEXT, classified to an SPDX id —
// the original behavior, now the fallback when no declared license was found.
//
// Returns the number of components changed. Best-effort; reads JARs read-only, no network, never fails
// the scan. Declared names are emitted verbatim; the downstream license scanner normalizes them to SPDX.
func (r *Resolver) Resolve(ctx context.Context, wsDir string, comps []sbom.Component) int {
	// Skip the work entirely unless something needs fixing: a missing license (fill) OR a multi-license
	// spray (override). A component with exactly one license is already clean.
	need := false
	for i := range comps {
		if n := len(comps[i].Licenses); n == 0 || n >= 2 {
			need = true
			break
		}
	}
	if !need || strings.TrimSpace(wsDir) == "" {
		return 0
	}
	index, ambiguous, declared := scanWorkspace(ctx, wsDir)
	if len(index) == 0 && len(declared) == 0 {
		return 0
	}
	resolved := 0
	for i := range comps {
		c := &comps[i]
		n := len(c.Licenses)
		key := c.Name + "@" + c.Version
		// Declared pom license is authoritative: override the spray or fill a gap.
		if dl := declared[key]; len(dl) > 0 && (n == 0 || n >= 2) {
			lics := make([]sbom.License, 0, len(dl))
			for _, name := range dl {
				lics = append(lics, sbom.License{Name: name})
			}
			c.Licenses = lics
			c.LicenseSource = sbom.LicenseSourceManifest
			c.LicenseConfidence = "declared"
			c.UnknownReason = ""
			resolved++
			continue
		}
		// Fallback: fill a still-missing license from embedded license text.
		if n == 0 && !ambiguous[key] {
			if id := index[key]; id != "" {
				c.Licenses = []sbom.License{{SPDXID: id, Name: id}}
				c.LicenseSource = sbom.LicenseSourceLicenseFile
				c.LicenseConfidence = "declared"
				c.UnknownReason = ""
				resolved++
			}
		}
	}
	return resolved
}

type entry struct {
	key      string   // artifactId@version from the JAR's pom.properties
	spdx     string   // SPDX id CONCLUDED from the JAR's embedded license text
	declared []string // license names DECLARED in the JAR's embedded pom.xml <licenses>
}

// scanWorkspace indexes, per "artifact@version": the SPDX id CONCLUDED from JAR license text
// (a key seen with two different ids is marked ambiguous and removed — never guessed), and the
// license names DECLARED in the JAR's embedded pom.xml (first non-empty wins; declared is
// authoritative so it is not subject to the concluded-text ambiguity guard).
func scanWorkspace(ctx context.Context, wsDir string) (index map[string]string, ambiguous map[string]bool, declared map[string][]string) {
	index = map[string]string{}
	ambiguous = map[string]bool{}
	declared = map[string][]string{}
	count := 0
	add := func(e entry) {
		if e.key != "" && len(e.declared) > 0 {
			if _, ok := declared[e.key]; !ok {
				declared[e.key] = e.declared
			}
		}
		if e.key == "" || e.spdx == "" {
			return
		}
		if ambiguous[e.key] {
			return
		}
		if prev, ok := index[e.key]; ok {
			if prev != e.spdx {
				ambiguous[e.key] = true
				delete(index, e.key)
			}
			return
		}
		index[e.key] = e.spdx
	}
	_ = filepath.WalkDir(wsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Skip dirs + non-regular files: a symlink ending.jar could redirect zip.OpenReader
		// to an arbitrary host path (mirrors the workspace symlink guard elsewhere).
		if d.IsDir() || !d.Type().IsRegular() || !isJAR(d.Name()) {
			return nil
		}
		if count >= maxJARs {
			return filepath.SkipAll
		}
		count++
		for _, e := range entriesFromJARFile(ctx, path) {
			add(e)
		}
		return nil
	})
	return index, ambiguous, declared
}

func isJAR(name string) bool {
	n := strings.ToLower(name)
	return strings.HasSuffix(n, ".jar") || strings.HasSuffix(n, ".war") || strings.HasSuffix(n, ".ear")
}

func entriesFromJARFile(ctx context.Context, path string) []entry {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil
	}
	defer func() { _ = zr.Close() }()
	return entriesFromZip(ctx, &zr.Reader, 1)
}

// entriesFromZip pairs a JAR's own coordinate (from pom.properties) with the SPDX id of
// its embedded license text, descending depth more levels into nested JARs. It honors
// ctx cancellation between entries so a single hostile archive can't outlive a timeout.
func entriesFromZip(ctx context.Context, zr *zip.Reader, depth int) []entry {
	var coordKey, coordDir, spdx string
	declaredByDir := map[string][]string{} // pom.xml dir -> declared license names
	var out []entry
	for i, f := range zr.File {
		if i >= maxEntriesPerJAR || ctx.Err() != nil {
			break
		}
		switch {
		case strings.HasPrefix(f.Name, "META-INF/maven/") && strings.HasSuffix(f.Name, "/pom.properties"):
			if k := coordFromPomProperties(f); k != "" {
				coordKey, coordDir = k, zipDir(f.Name)
			}
		case strings.HasPrefix(f.Name, "META-INF/maven/") && strings.HasSuffix(f.Name, "/pom.xml"):
			if names := declaredFromPomXML(f); len(names) > 0 {
				declaredByDir[zipDir(f.Name)] = names
			}
		case isLicenseEntry(f.Name):
			if id := classifyEntry(f); id != "" && spdx == "" {
				spdx = id
			}
		case depth > 0 && isJAR(f.Name) && f.UncompressedSize64 > 0 && f.UncompressedSize64 <= maxNestedBytes:
			out = append(out, entriesFromNestedJAR(ctx, f, depth-1)...)
		}
	}
	// Emit when we know the JAR's coordinate — even if only the declared pom license (not concluded
	// text) was found. The declared license is taken from the pom.xml SIBLING of the winning
	// pom.properties, so a bundled dependency's pom cannot be mis-attributed to this artifact.
	if coordKey != "" {
		out = append(out, entry{key: coordKey, spdx: spdx, declared: declaredByDir[coordDir]})
	}
	return out
}

// zipDir returns the directory portion (with trailing slash) of a zip entry path.
func zipDir(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[:i+1]
	}
	return ""
}

// declaredFromPomXML extracts the license names DECLARED in a Maven pom.xml's <licenses> block —
// the artifact's own legal declaration. XML element matching is by local name, so the Maven POM
// namespace is handled without hard-coding it. A pom whose licenses are inherited from a parent
// (not present in the embedded pom) yields nothing, and the caller falls back to text/leaves as-is.
func declaredFromPomXML(f *zip.File) []string {
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, maxPomBytes))
	if err != nil || len(data) == 0 {
		return nil
	}
	var p struct {
		Licenses []struct {
			Name string `xml:"name"`
			URL  string `xml:"url"`
		} `xml:"licenses>license"`
	}
	if xml.Unmarshal(data, &p) != nil {
		return nil
	}
	out := make([]string, 0, len(p.Licenses))
	for _, l := range p.Licenses {
		name := strings.TrimSpace(l.Name)
		if name == "" {
			name = strings.TrimSpace(l.URL) // some poms declare only a URL
		}
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

func entriesFromNestedJAR(ctx context.Context, f *zip.File, depth int) []entry {
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, maxNestedBytes))
	if err != nil {
		return nil
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil
	}
	return entriesFromZip(ctx, zr, depth)
}

// isLicenseEntry matches common license-text file names at any depth in the archive.
func isLicenseEntry(name string) bool {
	base := strings.ToLower(filepath.Base(name))
	for _, p := range []string{"license", "licence", "copying", "unlicense"} {
		if base == p || strings.HasPrefix(base, p+".") {
			return true
		}
	}
	return false
}

// classifyEntry reads a license file and returns the best SPDX id (or "" if no strong match).
func classifyEntry(f *zip.File) string {
	rc, err := f.Open()
	if err != nil {
		return ""
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, maxLicenseBytes))
	if err != nil || len(data) == 0 {
		return ""
	}
	id, _, ok := licensetext.Classify(data, 0) // 0 → DefaultMinConfidence; shared with licensefile
	if !ok {
		return ""
	}
	return id
}

// coordFromPomProperties returns "artifactId@version" from a pom.properties entry.
func coordFromPomProperties(f *zip.File) string {
	rc, err := f.Open()
	if err != nil {
		return ""
	}
	defer func() { _ = rc.Close() }()
	var artifact, version string
	sc := bufio.NewScanner(io.LimitReader(rc, maxPropsBytes))
	sc.Buffer(make([]byte, 0, 64*1024), maxPropsBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "artifactId":
			artifact = strings.TrimSpace(v)
		case "version":
			version = strings.TrimSpace(v)
		}
	}
	if artifact == "" || version == "" {
		return ""
	}
	return artifact + "@" + version
}
