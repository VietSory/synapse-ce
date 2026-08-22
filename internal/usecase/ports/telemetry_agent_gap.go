package ports

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TelemetryAgentGap is durable agent-origin loss evidence. Unlike a delivery gap,
// KnownSequence may be false when local corruption destroyed the coordinate itself.
type TelemetryAgentGap struct {
	TenantID        shared.ID
	HostID          shared.ID
	AssetID         shared.ID
	AgentID         shared.ID
	AgentSessionID  fleetagent.SessionID
	StreamID        shared.ID
	Priority        fleetagent.DeliveryPriority
	Epoch           uint64
	GapID           shared.ID
	KnownSequence   bool
	FromSequence    uint64
	ToSequence      uint64
	Reason          string
	Count           uint64
	OccurredAt      time.Time
	ReceivedAt      time.Time
}

func (g TelemetryAgentGap) Validate() error {
	if g.TenantID.IsZero() || g.HostID.IsZero() || g.AssetID.IsZero() || g.AgentID.IsZero() || g.AgentSessionID == "" || g.StreamID.IsZero() || g.GapID.IsZero() {
		return fmt.Errorf("%w: telemetry agent gap identity is incomplete", shared.ErrValidation)
	}
	if !g.Priority.Valid() || g.Epoch == 0 || g.Reason == "" || g.Count == 0 || g.OccurredAt.IsZero() || g.ReceivedAt.IsZero() {
		return fmt.Errorf("%w: telemetry agent gap metadata is incomplete", shared.ErrValidation)
	}
	if g.KnownSequence {
		if g.FromSequence == 0 || g.ToSequence < g.FromSequence || g.Count != g.ToSequence-g.FromSequence+1 {
			return fmt.Errorf("%w: telemetry agent gap range/count is invalid", shared.ErrValidation)
		}
	} else if g.FromSequence != 0 || g.ToSequence != 0 {
		return fmt.Errorf("%w: unknown-coordinate telemetry agent gap cannot claim a range", shared.ErrValidation)
	}
	return nil
}

type TelemetryAgentGapStore interface {
	IngestAgentGap(ctx context.Context, gap TelemetryAgentGap) error
	QueryAgentGaps(ctx context.Context, q HuntQuery) ([]TelemetryAgentGap, error)
}
