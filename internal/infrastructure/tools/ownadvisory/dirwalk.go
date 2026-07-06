package ownadvisory

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// walkJSONAdvisories is the hardened, shared core of the directory-backed advisory feeds (DirFeed for OSV,
// CSAFDirFeed for CSAF): it walks dir for *.json files, parses each with parse, and emits every resulting
// advisory via emit. Keeping ONE copy of this security-sensitive walk (rather than one per feed) means a
// hardening fix can never drift between them.
//
// Hardening (parity with the ownsbom walk): a directory-level I/O error or context cancellation ABORTS; a
// non-regular file is skipped (no symlink escape); each file is size-capped via an Lstat re-checked right
// before the read (TOCTOU narrowing); the file count is bounded; and an unparseable/oversized/unreadable
// file is SKIPPED + counted (one bad record must never abort a bulk sync). It returns the count of skipped
// FILES and a fatal error. ADVISORY-level skipping (e.g. an inert empty-Affected advisory) is the caller's
// concern, applied inside emit — this walk only counts file-level skips.
func walkJSONAdvisories(ctx context.Context, dir string, parse func([]byte) ([]advisory.Advisory, error), emit func(advisory.Advisory) error) (int, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return 0, fmt.Errorf("stat advisory dir: %w", err)
	}
	if !info.IsDir() {
		return 0, fmt.Errorf("%w: advisory feed path must be a directory, got %q", shared.ErrValidation, dir)
	}
	skipped, files := 0, 0
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // symlink/device/etc — never follow out of the tree
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			return nil
		}
		if files++; files > maxAdvisoryFiles {
			return fmt.Errorf("%w: advisory dir exceeds %d files; refusing to ingest", shared.ErrValidation, maxAdvisoryFiles)
		}
		// Re-stat via Lstat right before the read (TOCTOU narrowing + authoritative size); never follow a
		// symlink swapped in after WalkDir cached the entry type.
		fi, lerr := os.Lstat(path)
		if lerr != nil {
			skipped++
			return nil
		}
		if !fi.Mode().IsRegular() {
			skipped++ // a non-regular swapped in within the Lstat window — not read (the guard holds); count it for an honest skip total
			return nil
		}
		if fi.Size() > maxAdvisoryBytes {
			skipped++ // an over-cap file is one bad record, not a reason to abort the whole sync
			return nil
		}
		content, rerr := os.ReadFile(path) // #nosec G304 -- WalkDir entry under dir, re-verified regular (non-symlink) via Lstat immediately above
		if rerr != nil {
			skipped++
			return nil
		}
		advs, perr := parse(content)
		if perr != nil {
			skipped++ // a malformed advisory file is skipped + counted, never aborts the sync
			return nil
		}
		for _, adv := range advs {
			if eerr := emit(adv); eerr != nil {
				return eerr
			}
		}
		return nil
	})
	if walkErr != nil {
		return skipped, fmt.Errorf("walk advisory dir: %w", walkErr)
	}
	return skipped, nil
}
