package telemetry

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// WithDeliveryGaps preserves the original A3 decorator contract. If the store also
// exposes agent-origin gaps, those participate automatically; otherwise only durable
// delivery-sequence holes affect completeness.
func WithDeliveryGaps(store ports.TelemetryStore) ports.TelemetryStore {
	delivery, ok := store.(ports.TelemetryGapReader)
	if !ok {
		return store
	}
	agent, _ := store.(ports.TelemetryAgentGapReader)
	return withTransportGapReaders(store, delivery, agent)
}

// WithAgentGaps attaches a separate agent-origin gap reader to a telemetry store.
// This is used when transport loss is persisted in a dedicated repository rather
// than in the event store itself. Existing delivery gaps remain active when present.
func WithAgentGaps(store ports.TelemetryStore, agent ports.TelemetryAgentGapReader) ports.TelemetryStore {
	if store == nil || agent == nil {
		return store
	}
	delivery, _ := store.(ports.TelemetryGapReader)
	return withTransportGapReaders(store, delivery, agent)
}

type deliveryAwareStore struct {
	ports.TelemetryStore
	delivery ports.TelemetryGapReader
	agent    ports.TelemetryAgentGapReader
}

func withTransportGapReaders(store ports.TelemetryStore, delivery ports.TelemetryGapReader, agent ports.TelemetryAgentGapReader) ports.TelemetryStore {
	if delivery == nil && agent == nil {
		return store
	}
	return &deliveryAwareStore{TelemetryStore: store, delivery: delivery, agent: agent}
}

func (s *deliveryAwareStore) Query(ctx context.Context, q ports.HuntQuery) (ports.HuntResult, error) {
	result, err := s.TelemetryStore.Query(ctx, q)
	if err != nil {
		return ports.HuntResult{}, err
	}
	if s.delivery != nil {
		gaps, err := s.delivery.QueryDeliveryGaps(ctx, q)
		if err != nil {
			return ports.HuntResult{}, err
		}
		if len(gaps) > 0 {
			result.Complete = false
		}
	}
	if s.agent != nil {
		gaps, err := s.agent.QueryAgentGaps(ctx, q)
		if err != nil {
			return ports.HuntResult{}, err
		}
		if len(gaps) > 0 {
			result.Complete = false
		}
	}
	return result, nil
}

var _ ports.TelemetryStore = (*deliveryAwareStore)(nil)
