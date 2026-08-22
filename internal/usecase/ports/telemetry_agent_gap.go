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

// SameEvidence reports whether two rows represent the exact same signed loss evidence.
// ReceivedAt is server-owned admission metadata and is deliberately excluded.
func (g TelemetryAgentGap) SameEvidence(other TelemetryAgentGap) bool {
	return g.TenantID == other.TenantID && g.HostID == other.HostID && g.AssetID == other.AssetID && g.AgentID == other.AgentID &&
		g.AgentSessionID == other.AgentSessionID && g.StreamID == other.StreamID && g.Priority == other.Priority && g.Epoch == other.Epoch &&
		g.GapID == other.GapID && g.KnownSequence == other.KnownSequence && g.FromSequence == other.FromSequence &&
		g.ToSequence == other.ToSequence && g.Reason == other.Reason && g.Count == other.Count && g.OccurredAt.Equal(other.OccurredAt)
}

// MonotonicExtensionOf permits one stable local GapID to grow while it is being
// coalesced concurrently with transport. Immutable attribution must match exactly;
// evidence may only grow, never shrink or be re-pointed to another reason/lane.
func (g TelemetryAgentGap) MonotonicExtensionOf(previous TelemetryAgentGap) bool {
	if g.TenantID != previous.TenantID || g.HostID != previous.HostID || g.AssetID != previous.AssetID || g.AgentID != previous.AgentID ||
		g.AgentSessionID != previous.AgentSessionID || g.StreamID != previous.StreamID || g.Priority != previous.Priority || g.Epoch != previous.Epoch ||
		g.GapID != previous.GapID || g.KnownSequence != previous.KnownSequence || g.Reason != previous.Reason || !g.OccurredAt.Equal(previous.OccurredAt) {
		return false
	}
	if !g.KnownSequence {
		return g.FromSequence == 0 && g.ToSequence == 0 && g.Count >= previous.Count
	}
	return g.FromSequence <= previous.FromSequence && g.ToSequence >= previous.ToSequence && g.Count >= previous.Count
}

// TelemetryAgentGapReader is the narrow retro-hunt view of durable agent-origin
// loss. Hunt consumers do not need authority to write or mutate the evidence.
type TelemetryAgentGapReader interface {
	QueryAgentGaps(ctx context.Context, q HuntQuery) ([]TelemetryAgentGap, error)
}

type TelemetryAgentGapStore interface {
	TelemetryAgentGapReader
	IngestAgentGap(ctx context.Context, gap TelemetryAgentGap) error
}
