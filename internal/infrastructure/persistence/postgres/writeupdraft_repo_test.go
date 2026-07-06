package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeupdraft"
)

// fakeWriteupRow implements rowScanner with fixed values, so scanWriteupDraft's fail-closed enum check
// can be exercised without a database (the full repo paths are DB-gated integration tests).
type fakeWriteupRow struct {
	id, eid, fid, desc, rem, state, proposedBy, decidedBy string
	created, updated                                      time.Time
	err                                                   error
}

func (f fakeWriteupRow) Scan(dest ...any) error {
	if f.err != nil {
		return f.err
	}
	vals := []any{f.id, f.eid, f.fid, f.desc, f.rem, f.state, f.proposedBy, f.decidedBy}
	for i, v := range vals {
		*(dest[i].(*string)) = v.(string)
	}
	*(dest[8].(*time.Time)) = f.created
	*(dest[9].(*time.Time)) = f.updated
	return nil
}

func TestScanWriteupDraftValid(t *testing.T) {
	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	d, err := scanWriteupDraft(fakeWriteupRow{
		id: "wd:1", eid: "eng:1", fid: "find:1", desc: "desc", rem: "rem",
		state: string(writeupdraft.StateAccepted), proposedBy: "agent:w", decidedBy: "user:r",
		created: now, updated: now,
	})
	if err != nil {
		t.Fatalf("scan valid: %v", err)
	}
	if d.ID != "wd:1" || d.FindingID != "find:1" || d.State != writeupdraft.StateAccepted || d.DecidedBy != "user:r" {
		t.Errorf("scanned draft wrong: %+v", d)
	}
}

func TestScanWriteupDraftFailClosedOnBadState(t *testing.T) {
	for _, bad := range []string{"", "bogus", "PROPOSED", "published"} {
		_, err := scanWriteupDraft(fakeWriteupRow{
			id: "wd:1", eid: "eng:1", fid: "find:1", desc: "d", state: bad,
		})
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("stored state %q must be rejected with ErrValidation, got %v", bad, err)
		}
	}
}

func TestScanWriteupDraftPropagatesScanError(t *testing.T) {
	want := errors.New("boom")
	if _, err := scanWriteupDraft(fakeWriteupRow{err: want}); !errors.Is(err, want) {
		t.Errorf("scan error must propagate, got %v", err)
	}
}
