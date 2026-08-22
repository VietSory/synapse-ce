package spool

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestAckGapRemovesEvidenceDurably(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.Dir = dir
	cfg.Session = fleetagent.SessionID("session-gap-ack")
	cfg.Boot = fleetagent.BootID("boot-gap-ack")
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gap := ports.SpoolGap{
		ID: "gap-ack-1", Priority: fleetagent.PriorityP3, Epoch: 1,
		KnownSequence: false, Reason: ports.SpoolGapQuotaEviction, Count: 2,
		OccurredAt: time.Now().UTC(),
	}
	s.mu.Lock()
	if err := s.appendGapLocked(gap); err != nil {
		s.mu.Unlock()
		t.Fatalf("append gap: %v", err)
	}
	s.mu.Unlock()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Before ACK, restart must recover the durable loss record.
	s, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gaps, err := s.Gaps(context.Background())
	if err != nil || len(gaps) != 1 || gaps[0].ID != gap.ID {
		t.Fatalf("recovered gaps=%+v err=%v", gaps, err)
	}
	removed, err := s.AckGap(context.Background(), gap)
	if err != nil || !removed {
		t.Fatalf("ack gap: removed=%t err=%v", removed, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// The ACK rewrite is durable: another restart must not resurrect the gap.
	s, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	gaps, err = s.Gaps(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 0 {
		t.Fatalf("ACKed gap resurrected after restart: %+v", gaps)
	}
	removed, err = s.AckGap(context.Background(), gap)
	if err != nil || !removed {
		t.Fatalf("repeated gap ACK must be idempotent: removed=%t err=%v", removed, err)
	}
}

func TestAckGapDoesNotDeleteEvidenceThatGrewInFlight(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Dir = t.TempDir()
	cfg.Session = fleetagent.SessionID("session-gap-race")
	cfg.Boot = fleetagent.BootID("boot-gap-race")
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	snapshot := ports.SpoolGap{
		ID: "gap-race-1", Priority: fleetagent.PriorityP3, Epoch: 1,
		KnownSequence: false, Reason: ports.SpoolGapQuotaEviction, Count: 1,
		OccurredAt: time.Now().UTC(),
	}
	s.mu.Lock()
	if err := s.appendGapLocked(snapshot); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	// Simulate a producer coalescing one more loss while the first snapshot is on wire.
	s.gaps[0].Count = 2
	s.gapDirty = true
	if err := s.flushGapJournalLocked(); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()

	removed, err := s.AckGap(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Fatal("stale ACK deleted a gap that grew while the request was in flight")
	}
	current, err := s.Gaps(context.Background())
	if err != nil || len(current) != 1 || current[0].Count != 2 {
		t.Fatalf("newer evidence was not retained: gaps=%+v err=%v", current, err)
	}
	removed, err = s.AckGap(context.Background(), current[0])
	if err != nil || !removed {
		t.Fatalf("current snapshot ACK failed: removed=%t err=%v", removed, err)
	}
}
