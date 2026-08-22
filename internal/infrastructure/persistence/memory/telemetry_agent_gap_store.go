package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TelemetryAgentGapStore is the memory-mode durable boundary for agent-origin
// spool loss. It is separate from delivery-sequence gaps so late-fill reconciliation
// can never erase evidence of local quota/corruption loss.
type TelemetryAgentGapStore struct {
	mu       sync.Mutex
	byTenant map[shared.ID]map[shared.ID]ports.TelemetryAgentGap
}

func NewTelemetryAgentGapStore() *TelemetryAgentGapStore {
	return &TelemetryAgentGapStore{byTenant: map[shared.ID]map[shared.ID]ports.TelemetryAgentGap{}}
}

func (s *TelemetryAgentGapStore) IngestAgentGap(ctx context.Context, gap ports.TelemetryAgentGap) error {
	if err := gap.Validate(); err != nil {
		return err
	}
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() {
		return fmt.Errorf("%w: telemetry agent gap requires tenant context", shared.ErrValidation)
	}
	if tenant != gap.TenantID {
		return fmt.Errorf("%w: telemetry agent gap tenant disagrees with context", shared.ErrForbidden)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byTenant[tenant] == nil {
		s.byTenant[tenant] = map[shared.ID]ports.TelemetryAgentGap{}
	}
	if existing, found := s.byTenant[tenant][gap.GapID]; found {
		if !sameTelemetryAgentGap(existing, gap) {
			return fmt.Errorf("%w: telemetry agent gap id %q is already bound to different evidence", shared.ErrConflict, gap.GapID)
		}
		return nil
	}
	s.byTenant[tenant][gap.GapID] = gap
	return nil
}

func (s *TelemetryAgentGapStore) QueryAgentGaps(ctx context.Context, q ports.HuntQuery) ([]ports.TelemetryAgentGap, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() {
		return nil, fmt.Errorf("%w: telemetry agent gap query requires tenant context", shared.ErrValidation)
	}
	var priority *fleetagent.DeliveryPriority
	if q.Class != "" {
		p, err := fleetagent.TelemetryPriority(q.Class)
		if err != nil {
			return nil, err
		}
		priority = &p
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ports.TelemetryAgentGap, 0)
	for _, gap := range s.byTenant[tenant] {
		if q.HostID != "" && q.HostID != gap.HostID {
			continue
		}
		if q.AssetID != "" && q.AssetID != gap.AssetID {
			continue
		}
		if priority != nil && *priority != gap.Priority {
			continue
		}
		if !q.Since.IsZero() && gap.OccurredAt.Before(q.Since) {
			continue
		}
		if !q.Until.IsZero() && gap.OccurredAt.After(q.Until) {
			continue
		}
		out = append(out, gap)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OccurredAt.Equal(out[j].OccurredAt) {
			return out[i].GapID < out[j].GapID
		}
		return out[i].OccurredAt.Before(out[j].OccurredAt)
	})
	return out, nil
}

func sameTelemetryAgentGap(a, b ports.TelemetryAgentGap) bool {
	return a.TenantID == b.TenantID && a.HostID == b.HostID && a.AssetID == b.AssetID && a.AgentID == b.AgentID &&
		a.AgentSessionID == b.AgentSessionID && a.StreamID == b.StreamID && a.Priority == b.Priority && a.Epoch == b.Epoch &&
		a.GapID == b.GapID && a.KnownSequence == b.KnownSequence && a.FromSequence == b.FromSequence &&
		a.ToSequence == b.ToSequence && a.Reason == b.Reason && a.Count == b.Count && a.OccurredAt.Equal(b.OccurredAt)
}

var _ ports.TelemetryAgentGapStore = (*TelemetryAgentGapStore)(nil)
