package telemetry

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// WithDeliveryGaps decorates an existing telemetry store so retro-hunt completeness
// includes first-class A3 transport gaps. The underlying event/loss/query semantics are
// unchanged; only an unresolved gap intersecting the query can turn Complete from true
// to false. Stores without the A3 gap reader are returned unchanged for compatibility.
func WithDeliveryGaps(store ports.TelemetryStore) ports.TelemetryStore {
	reader, ok := store.(ports.TelemetryGapReader)
	if !ok {
		return store
	}
	return &deliveryAwareStore{TelemetryStore: store, gaps: reader}
}

type deliveryAwareStore struct {
	ports.TelemetryStore
	gaps ports.TelemetryGapReader
}

func (s *deliveryAwareStore) Query(ctx context.Context, q ports.HuntQuery) (ports.HuntResult, error) {
	result, err := s.TelemetryStore.Query(ctx, q)
	if err != nil {
		return ports.HuntResult{}, err
	}
	gaps, err := s.gaps.QueryDeliveryGaps(ctx, q)
	if err != nil {
		return ports.HuntResult{}, err
	}
	if len(gaps) > 0 {
		result.Complete = false
	}
	return result, nil
}

var _ ports.TelemetryStore = (*deliveryAwareStore)(nil)
var _ = shared.ErrValidation // retain the package's shared-domain import boundary in architecture checks.
