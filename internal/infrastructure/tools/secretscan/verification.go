package secretscan

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// VisitRawSecret re-opens exactly one already-reported worktree finding and, when the same rule still matches
// the same redacted value at the same line, invokes visit with the raw credential. The raw value is never
// returned or stored. This narrow callback seam exists only for opt-in active verification; ordinary scanning
// keeps the stronger invariant that SecretRawFinding contains redacted material only.
//
// The file is opened through os.Root, is size/type checked before and after the read, and the detector's normal
// allow-list, comment mask, inline allow, entropy, and lineSkip rules are re-applied. Historical/archive/decoded
// findings deliberately return found=false rather than reconstructing or guessing credential material.
func (s *Scanner) VisitRawSecret(ctx context.Context, root string, hit ports.SecretRawFinding, visit func(string) error) (found bool, err error) {
	if visit == nil {
		return false, fmt.Errorf("secret verification: nil visitor")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if hit.FromHistory || strings.TrimSpace(hit.File) == "" || hit.Line <= 0 || strings.TrimSpace(hit.RuleID) == "" {
		return false, nil
	}

	var detector *rule
	for i := range s.rules {
		if s.rules[i].id == hit.RuleID {
			detector = &s.rules[i]
			break
		}
	}
	if detector == nil {
		return false, nil
	}

	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return false, fmt.Errorf("secret verification root: %w", err)
	}
	rel := filepath.Clean(filepath.FromSlash(hit.File))
	if filepath.IsAbs(rel) || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false, nil
	}
	rootDir, err := os.OpenRoot(rootAbs)
	if err != nil {
		return false, fmt.Errorf("secret verification root: %w", err)
	}
	defer func() {
		if closeErr := rootDir.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close secret verification root: %w", closeErr)
		}
	}()
	f, err := rootDir.OpenFile(rel, os.O_RDONLY, 0)
	if err != nil {
		return false, nil // candidate disappeared after the deterministic scan: verification becomes unknown
	}
	defer func() { _ = f.Close() }()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maxFileBytes {
		return false, nil
	}
	data, readErr := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if readErr != nil || len(data) == 0 || len(data) > maxFileBytes {
		return false, nil
	}
	after, statErr := f.Stat()
	if statErr != nil || !stableFileSnapshot(before, after, int64(len(data))) {
		return false, nil
	}

	original := string(data)
	masked := string(maskComments(hit.File, data))
	if !hasAnyKeyword(masked, detector.keywords) {
		return false, nil
	}
	for _, m := range detector.re.FindAllStringSubmatchIndex(masked, -1) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		start, end := m[0], m[1]
		if detector.group > 0 && len(m) > 2*detector.group+1 && m[2*detector.group] >= 0 {
			start, end = m[2*detector.group], m[2*detector.group+1]
		}
		if start < 0 || end <= start || end > len(masked) {
			continue
		}
		line := 1 + strings.Count(masked[:start], "\n")
		if line != hit.Line {
			continue
		}
		secret := masked[start:end]
		if s.allowed(secret, detector.allow) || inlineAllow(lineOf(original, start)) {
			continue
		}
		if detector.lineSkip != nil && detector.lineSkip(lineOf(masked, start)) {
			continue
		}
		if detector.minEnt > 0 && shannon(secret) < detector.minEnt {
			continue
		}
		if redactMatch(secret) != hit.Match {
			continue
		}
		if err := visit(secret); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}
