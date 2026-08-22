package memory

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func (s *TelemetryTransportStore) CommitBatch(ctx context.Context, batch ports.TelemetryEventBatch) error {
	if err := batch.Validate(); err != nil {
		return err
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.commits[tenant] == nil {
		s.commits[tenant] = map[batchKey]storedBatchCommit{}
	}
	coord := batchKey{batch.AgentID, batch.StreamID, batch.Epoch, batch.Sequence}
	want := storedBatchCommit{
		batchID: batch.BatchID, payloadDigest: batch.PayloadDigest, asset: batch.AssetID,
		schemaVersion: batch.SchemaVersion, eventCount: len(batch.Events),
	}
	if existing, ok := s.commits[tenant][coord]; ok {
		if existing != want {
			return fmt.Errorf("%w: telemetry delivery sequence is already committed to a different batch", shared.ErrConflict)
		}
		return nil
	}
	s.commits[tenant][coord] = want
	return nil
}
