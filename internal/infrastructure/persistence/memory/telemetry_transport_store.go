package memory

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TelemetryTransportStore composes the in-memory event/delivery ledger with the
// agent-origin loss ledger. Keeping both under one production-facing value lets
// highest-contiguous ACKs treat a signed, durable known loss as a terminal
// sequence outcome without teaching the generic TelemetryStore about transport
// admission concerns.
type TelemetryTransportStore struct {
	*TelemetryStore
	agentGaps *TelemetryAgentGapStore
}

func NewTelemetryTransportStore(hot, warm time.Duration) *TelemetryTransportStore {
	return &TelemetryTransportStore{
		TelemetryStore: NewTelemetryStore(hot, warm),
		agentGaps:      NewTelemetryAgentGapStore(),
	}
}

func (s *TelemetryTransportStore) IngestAgentGap(ctx context.Context, gap ports.TelemetryAgentGap) error {
	return s.agentGaps.IngestAgentGap(ctx, gap)
}

func (s *TelemetryTransportStore) QueryAgentGaps(ctx context.Context, q ports.HuntQuery) ([]ports.TelemetryAgentGap, error) {
	return s.agentGaps.QueryAgentGaps(ctx, q)
}

func (s *TelemetryTransportStore) IngestDelivery(ctx context.Context, batch ports.TelemetryDeliveryBatch) (ports.TelemetryDeliveryResult, error) {
	result, err := s.TelemetryStore.IngestDelivery(ctx, batch)
	if err != nil {
		return ports.TelemetryDeliveryResult{}, err
	}
	tenant, err := requireTelemetryTenant(ctx)
	if err != nil {
		return ports.TelemetryDeliveryResult{}, err
	}
	m := batch.Manifest

	// Copy known-coordinate loss ranges without holding the loss-store lock while
	// acquiring the delivery-store lock. Gap ingest never needs the delivery lock,
	// so this keeps the two memory durability boundaries deadlock-free.
	s.agentGaps.mu.Lock()
	losses := make([]fleetagent.SeqRange, 0)
	for _, gap := range s.agentGaps.byTenant[tenant] {
		if !gap.KnownSequence || gap.StreamID != m.StreamID || gap.Priority != m.Priority || gap.Epoch != m.Epoch {
			continue
		}
		losses = append(losses, fleetagent.SeqRange{From: gap.FromSequence, To: gap.ToSequence})
	}
	s.agentGaps.mu.Unlock()
	if len(losses) == 0 {
		return result, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	lane := s.delivery[tenant][m.StreamID.String()]
	if lane == nil || lane.epochs[m.Epoch] == nil {
		// The base ingest already became durable. Returning an error is deliberate:
		// the agent retains WAL and an idempotent retry can repair ACK projection.
		return ports.TelemetryDeliveryResult{}, fmt.Errorf("telemetry transport ACK projection cannot find durable lane %s/%d", m.StreamID, m.Epoch)
	}
	delivered := make([]uint64, 0, len(lane.epochs[m.Epoch].sequences))
	for sequence := range lane.epochs[m.Epoch].sequences {
		delivered = append(delivered, sequence)
	}
	ack, err := fleetagent.HighestContiguousDurableOutcome(delivered, losses)
	if err != nil {
		return ports.TelemetryDeliveryResult{}, fmt.Errorf("project telemetry transport ACK: %w", err)
	}
	if ack <= result.ACK.Through {
		return result, nil
	}

	// Mirror the Postgres provenance projection: a batch becomes acknowledged once
	// every earlier coordinate has either an event or durable signed loss evidence.
	for batchID, stored := range lane.batches {
		if stored.manifest.StreamID != m.StreamID || stored.manifest.Epoch != m.Epoch || stored.manifest.Sequence > ack {
			continue
		}
		stored.state = ports.TelemetryStateAcknowledged
		lane.batches[batchID] = stored
	}
	result.ACK.Through = ack
	return result, nil
}

var _ ports.TelemetryDeliveryStore = (*TelemetryTransportStore)(nil)
var _ ports.TelemetryAgentGapStore = (*TelemetryTransportStore)(nil)
var _ ports.TelemetryStore = (*TelemetryTransportStore)(nil)
var _ ports.TelemetryGapReader = (*TelemetryTransportStore)(nil)
var _ ports.TelemetryAssetBindingStore = (*TelemetryTransportStore)(nil)
