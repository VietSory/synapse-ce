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
	if err != nil { t.Fatal(err) }
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
	if err := s.Close(); err != nil { t.Fatal(err) }

	// Before ACK, restart must recover the durable loss record.
	s, err = Open(cfg)
	if err != nil { t.Fatal(err) }
	gaps, err := s.Gaps(context.Background())
	if err != nil || len(gaps) != 1 || gaps[0].ID != gap.ID {
		t.Fatalf("recovered gaps=%+v err=%v", gaps, err)
	}
	if err := s.AckGap(context.Background(), gap.ID); err != nil {
		t.Fatalf("ack gap: %v", err)
	}
	if err := s.Close(); err != nil { t.Fatal(err) }

	// The ACK rewrite is durable: another restart must not resurrect the gap.
	s, err = Open(cfg)
	if err != nil { t.Fatal(err) }
	defer s.Close()
	gaps, err = s.Gaps(context.Background())
	if err != nil { t.Fatal(err) }
	if len(gaps) != 0 {
		t.Fatalf("ACKed gap resurrected after restart: %+v", gaps)
	}
	if err := s.AckGap(context.Background(), gap.ID); err != nil {
		t.Fatalf("repeated gap ACK must be idempotent: %v", err)
	}
}
