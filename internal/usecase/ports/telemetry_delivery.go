package ports

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

// TelemetryBatchState is the durable provenance state of one accepted transport batch.
type TelemetryBatchState string

const (
	TelemetryStateReceived     TelemetryBatchState = "received"
	TelemetryStateDurable      TelemetryBatchState = "telemetry_durable"
	TelemetryStateAcknowledged TelemetryBatchState = "acknowledged"
)

// TelemetryDeliveryBatch is the trusted, decoded write handed to persistence after the use case has
// authenticated identity, verified the purpose-bound signing key, checked schema/version commitments,
// and stamped ReceivedAt. HostID is server-authoritative and must match the signed manifest.
type TelemetryDeliveryBatch struct {
	TenantID        shared.ID
	HostID          shared.ID
	AssetID         shared.ID
	AgentID         shared.ID
	AgentSessionID  fleetagent.SessionID
	Manifest        fleetagent.TelemetryBatchManifest
	KeyID           string
	Envelopes       []telemetry.TelemetryEnvelope
	ProjectedEvents []detection.Event
	ReceivedAt      time.Time
}

// Validate checks the invariants persistence relies on. Signature verification intentionally lives in
// the use case because a store must never become a second, divergent trust boundary.
func (b TelemetryDeliveryBatch) Validate() error {
	if b.TenantID.IsZero() || b.HostID.IsZero() || b.AssetID.IsZero() || b.AgentID.IsZero() || b.AgentSessionID == "" {
		return fmt.Errorf("%w: telemetry delivery identity is incomplete", shared.ErrValidation)
	}
	if err := b.Manifest.Validate(); err != nil {
		return err
	}
	if b.Manifest.HostID != b.HostID || b.Manifest.AgentID != b.AgentID || b.Manifest.AssetID != b.AssetID || b.Manifest.AgentSessionID != b.AgentSessionID {
		return fmt.Errorf("%w: telemetry delivery identity disagrees with manifest", shared.ErrValidation)
	}
	if b.KeyID == "" || b.ReceivedAt.IsZero() {
		return fmt.Errorf("%w: telemetry delivery key/received-at is required", shared.ErrValidation)
	}
	if len(b.Envelopes) == 0 || len(b.Envelopes) != len(b.ProjectedEvents) || uint64(len(b.Envelopes)) != b.Manifest.KeptCount {
		return fmt.Errorf("%w: telemetry delivery event counts disagree", shared.ErrValidation)
	}
	for i := range b.Envelopes {
		if b.Envelopes[i].EventID != b.Manifest.EventIDs[i] {
			return fmt.Errorf("%w: telemetry delivery event %d disagrees with manifest event id", shared.ErrValidation, i)
		}
	}
	return nil
}

// TelemetryDeliveryACK is the highest-contiguous acknowledgement for one stream incarnation.
type TelemetryDeliveryACK struct {
	Priority fleetagent.DeliveryPriority `json:"priority"`
	Epoch    uint64                      `json:"epoch"`
	Through  uint64                      `json:"through"`
}

// TelemetryGap is a first-class, durable sequence hole. A resolved gap is retained for provenance but
// is excluded from current hunt completeness; unresolved gaps are queryable through TelemetryGapReader.
type TelemetryGap struct {
	TenantID       shared.ID
	HostID         shared.ID
	AssetID        shared.ID
	AgentID        shared.ID
	AgentSessionID fleetagent.SessionID
	StreamID       shared.ID
	Priority       fleetagent.DeliveryPriority
	Epoch          uint64
	FromSequence   uint64
	ToSequence     uint64
	FromAt         time.Time
	ToAt           time.Time
	DetectedAt     time.Time
	ResolvedAt     *time.Time
}

func (g TelemetryGap) Validate() error {
	if g.TenantID.IsZero() || g.HostID.IsZero() || g.AssetID.IsZero() || g.AgentID.IsZero() || g.AgentSessionID == "" || g.StreamID.IsZero() {
		return fmt.Errorf("%w: telemetry gap identity is incomplete", shared.ErrValidation)
	}
	if !g.Priority.Valid() || g.Epoch == 0 || g.FromSequence == 0 || g.ToSequence < g.FromSequence {
		return fmt.Errorf("%w: telemetry gap range/incarnation is invalid", shared.ErrValidation)
	}
	if g.DetectedAt.IsZero() || g.FromAt.IsZero() || g.ToAt.IsZero() || g.FromAt.After(g.ToAt) {
		return fmt.Errorf("%w: telemetry gap timestamps are invalid", shared.ErrValidation)
	}
	return nil
}

// TelemetryDeliveryResult reports durable ingest work plus the ACK calculated from persisted sequences.
type TelemetryDeliveryResult struct {
	ACK       TelemetryDeliveryACK
	NewEvents int
	Gaps      []TelemetryGap
}

// TelemetryDeliveryStore persists verified A3 batches idempotently and computes the durable ACK/gap set.
type TelemetryDeliveryStore interface {
	IngestDelivery(ctx context.Context, batch TelemetryDeliveryBatch) (TelemetryDeliveryResult, error)
}

// TelemetryGapReader is implemented by telemetry stores that persist A3 transport gaps. Keeping this a
// narrow companion interface lets legacy test fakes continue implementing TelemetryStore unchanged.
type TelemetryGapReader interface {
	QueryDeliveryGaps(ctx context.Context, q HuntQuery) ([]TelemetryGap, error)
}

// TelemetryAssetBinding is the server-side agent→canonical-asset mapping consumed by A3. Session identity
// is derived from the authenticated AgentID via fleetagent.CanonicalSessionID; AssetID is never derived
// from an agent-supplied display name or payload.
type TelemetryAssetBinding struct {
	TenantID  shared.ID
	AgentID   shared.ID
	AssetID   shared.ID
	UpdatedAt time.Time
}

// TelemetryAssetBindingStore owns the narrow A0.1 binding tail needed by live ingest and heartbeat.
type TelemetryAssetBindingStore interface {
	BindTelemetryAsset(ctx context.Context, binding TelemetryAssetBinding) error
	ResolveTelemetryAsset(ctx context.Context, agentID shared.ID) (shared.ID, error)
}
