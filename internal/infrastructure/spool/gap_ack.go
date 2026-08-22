package spool

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// AckGap durably removes one local loss-evidence record only after A3 confirms
// the same GapID is persisted server-side. Repeating an ACK is a no-op.
func (s *Spool) AckGap(ctx context.Context, gapID shared.ID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if gapID.IsZero() {
		return fmt.Errorf("telemetry spool gap ACK requires gap id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpenLocked(); err != nil {
		return err
	}
	index := -1
	for i := range s.gaps {
		if s.gaps[i].ID == gapID {
			index = i
			break
		}
	}
	if index < 0 {
		return nil
	}
	copy(s.gaps[index:], s.gaps[index+1:])
	s.gaps = s.gaps[:len(s.gaps)-1]
	s.gapDirty = true
	if err := s.flushGapJournalLocked(); err != nil {
		return fmt.Errorf("persist telemetry spool gap ACK: %w", err)
	}
	return nil
}
