package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeupdraft"
)

func draftAt(t *testing.T, id, eng string, sec int) writeupdraft.Draft {
	t.Helper()
	now := time.Date(2026, 6, 24, 12, 0, sec, 0, time.UTC)
	d, err := writeupdraft.Propose(shared.ID(id), shared.ID(eng), "find:1", "desc", "rem", "agent:w", now)
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	return d
}

func TestWriteupDraftStoreUpsertAndGet(t *testing.T) {
	s := NewWriteupDraftStore()
	ctx := context.Background()
	d := draftAt(t, "wd:1", "eng:1", 1)
	if err := s.Save(ctx, d); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Upsert: a second Save with the same id replaces in place (no duplicate row).
	acc, _ := d.Accept("user:rev", time.Date(2026, 6, 24, 12, 1, 0, 0, time.UTC))
	if err := s.Save(ctx, acc); err != nil {
		t.Fatalf("save (upsert): %v", err)
	}
	got, err := s.Get(ctx, "eng:1", "wd:1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.State != writeupdraft.StateAccepted {
		t.Errorf("upsert did not replace: state=%q", got.State)
	}
	list, _ := s.ListByEngagement(ctx, "eng:1")
	if len(list) != 1 {
		t.Errorf("upsert must not create a duplicate, got %d rows", len(list))
	}
}

func TestWriteupDraftStoreGetMissingAndTenantScope(t *testing.T) {
	s := NewWriteupDraftStore()
	ctx := context.Background()
	_ = s.Save(ctx, draftAt(t, "wd:1", "eng:1", 1))
	if _, err := s.Get(ctx, "eng:1", "nope"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("missing id should be ErrNotFound, got %v", err)
	}
	// A draft is only visible within its own engagement.
	if _, err := s.Get(ctx, "eng:2", "wd:1"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("cross-engagement Get must be ErrNotFound, got %v", err)
	}
}

func TestWriteupDraftStoreListDeterministicOrder(t *testing.T) {
	s := NewWriteupDraftStore()
	ctx := context.Background()
	// Insert out of created-at order; expect (created_at, id) ascending back.
	_ = s.Save(ctx, draftAt(t, "wd:3", "eng:1", 3))
	_ = s.Save(ctx, draftAt(t, "wd:1", "eng:1", 1))
	_ = s.Save(ctx, draftAt(t, "wd:2", "eng:1", 2))
	list, err := s.ListByEngagement(ctx, "eng:1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := []shared.ID{"wd:1", "wd:2", "wd:3"}
	for i, d := range list {
		if d.ID != want[i] {
			t.Errorf("order[%d] = %q, want %q", i, d.ID, want[i])
		}
	}
}
