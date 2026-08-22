package spool

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AckGap durably removes one local loss-evidence record only after A3 confirms
// the exact snapshot that was shipped. A gap may be coalesced while the HTTP request
// is in flight; an ACK for the older snapshot must never delete newer local loss.
// The bool reports whether that snapshot is no longer pending locally.
func (s *Spool) AckGap(ctx context.Context, expected ports.SpoolGap) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := expected.Validate(); err != nil {
		return false, fmt.Errorf("telemetry spool gap ACK snapshot: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpenLocked(); err != nil {
		return false, err
	}
	index := -1
	for i := range s.gaps {
		if s.gaps[i].ID == expected.ID {
			index = i
			break
		}
	}
	if index < 0 {
		return true, nil // repeated ACK after a durable prior removal
	}
	if !sameSpoolGapSnapshot(s.gaps[index], expected) {
		return false, nil // evidence grew while the request was in flight
	}
	copy(s.gaps[index:], s.gaps[index+1:])
	s.gaps = s.gaps[:len(s.gaps)-1]
	s.gapDirty = true
	if err := s.flushGapJournalLocked(); err != nil {
		return false, fmt.Errorf("persist telemetry spool gap ACK: %w", err)
	}
	return true, nil
}

func sameSpoolGapSnapshot(a, b ports.SpoolGap) bool {
	return a.ID == b.ID && a.Priority == b.Priority && a.Epoch == b.Epoch &&
		a.FromSequence == b.FromSequence && a.ToSequence == b.ToSequence && a.KnownSequence == b.KnownSequence &&
		a.Reason == b.Reason && a.Count == b.Count && a.OccurredAt.Equal(b.OccurredAt)
}
