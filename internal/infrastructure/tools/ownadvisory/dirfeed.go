package ownadvisory

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// (per-entry size + file-count caps live in limits.go; the hardened walk lives in dirwalk.go, shared with
// CSAFDirFeed.)

// DirFeed is an AdvisoryFeed over a local directory of OSV advisory JSON files: the OFFLINE /
// air-gapped ingestion path. Point it at an unpacked OSV bulk dump (the per-ecosystem `all.zip` extracted,
// or an osv-scanner offline DB) and it streams every advisory into the owned store via the hardened
// walkJSONAdvisories core: each *.json is parsed via ParseOSV; an unparseable/oversized/unreadable file is
// SKIPPED + counted (best-effort bulk ingest), while a directory-level I/O error or ctx cancellation aborts.
type DirFeed struct {
	dir string
}

// NewDirFeed returns a feed over the given directory of OSV JSON advisories.
func NewDirFeed(dir string) *DirFeed { return &DirFeed{dir: dir} }

var _ ports.AdvisoryFeed = (*DirFeed)(nil)

// Each walks the directory, parses every *.json advisory via ParseOSV, and invokes fn for each parseable
// one. It returns the count of files it skipped (unparseable/oversized/unreadable) and a fatal error.
func (f *DirFeed) Each(ctx context.Context, fn func(a advisory.Advisory) error) (int, error) {
	return walkJSONAdvisories(ctx, f.dir, parseOSVOne, fn)
}

// parseOSVOne adapts the single-advisory ParseOSV to the multi-advisory walk contract (OSV = one advisory
// per file).
func parseOSVOne(data []byte) ([]advisory.Advisory, error) {
	adv, err := ParseOSV(data)
	if err != nil {
		return nil, err
	}
	return []advisory.Advisory{adv}, nil
}
