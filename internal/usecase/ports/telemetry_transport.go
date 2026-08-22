package ports

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TelemetryTransportStore persists the AGENT→CONTROL-PLANE transport sequencing state (A3, #624).
// It is deliberately separate from the columnar TelemetryStore: this store owns delivery identity,
// immutable per-sequence commitments, highest-contiguous ACK state, and explicit delivery gaps.
type TelemetryTransportStore interface {
	TelemetryDeliveryGapReader
	StreamState(ctx context.Context, agentID, streamID shared.ID, epoch uint64) (TelemetryStreamState, error)
	SaveStreamState(ctx context.Context, state TelemetryStreamState) error
	MaxEpoch(ctx context.Context, agentID, streamID shared.ID) (uint64, error)
	ListGaps(ctx context.Context, agentID, streamID shared.ID) ([]TelemetryGap, error)
	// CommitBatch durably claims one delivery coordinate for the exact signed batch identity before the
	// use case decides whether the sequence is fresh or a replay. The same commitment is idempotent; a
	// different BatchID/PayloadDigest/schema/asset/event-count at the same coordinate is ErrConflict.
	CommitBatch(ctx context.Context, batch TelemetryEventBatch) error
	// IngestBatchEvents persists the raw events after CommitBatch has fixed the sequence commitment.
	IngestBatchEvents(ctx context.Context, batch TelemetryEventBatch) (int, error)
	CountBatchEvents(ctx context.Context, agentID, streamID shared.ID, epoch, sequence uint64) (int, error)
}

// TelemetryDeliveryGapReader is the narrow coverage-honesty view consumed by retro-hunt. The filter is
// tenant-scoped from ctx and windows gaps by observed-time OVERLAP, not by detection wall-clock.
type TelemetryDeliveryGapReader interface {
	QueryDeliveryGaps(ctx context.Context, q TelemetryGapQuery) ([]TelemetryGap, error)
}

// TelemetryGapQuery selects open A3 delivery gaps. AgentID is the canonical host identity for A0.1;
// AssetID supports asset pivots. Priority is optional so class-specific hunts can map to P2/P3.
type TelemetryGapQuery struct {
	AgentID  shared.ID
	AssetID  shared.ID
	Priority *fleetagent.DeliveryPriority
	Since    time.Time
	Until    time.Time
}

// TelemetryEventBatch is one accepted batch's durable transport commitment plus its raw events, already
// verified against the signed manifest by the ingest use case. EventTimeMin/Max are the signed observed-
// time bounds used to conservatively anchor any missing neighboring delivery sequences.
type TelemetryEventBatch struct {
	BatchID       shared.ID
	PayloadDigest string
	AgentID       shared.ID
	StreamID      shared.ID
	AssetID       shared.ID
	Priority      fleetagent.DeliveryPriority
	Epoch         uint64
	Sequence      uint64
	SchemaVersion int
	EventTimeMin  time.Time
	EventTimeMax  time.Time
	Events        []StoredTelemetryEvent
}

type StoredTelemetryEvent struct {
	EventID    shared.ID
	Class      detection.Class
	Digest     string
	Payload    []byte
	ObservedAt time.Time
}

func (b TelemetryEventBatch) Validate() error {
	if b.BatchID.IsZero() || b.PayloadDigest == "" {
		return fmt.Errorf("%w: telemetry event batch needs batch id and payload digest", shared.ErrValidation)
	}
	if b.AgentID.IsZero() || b.StreamID.IsZero() || b.AssetID.IsZero() {
		return fmt.Errorf("%w: telemetry event batch needs agent, stream and asset ids", shared.ErrValidation)
	}
	if !b.Priority.Valid() {
		return fmt.Errorf("%w: telemetry event batch has invalid priority %d", shared.ErrValidation, int(b.Priority))
	}
	if b.Epoch == 0 || b.Sequence == 0 {
		return fmt.Errorf("%w: telemetry event batch needs a non-zero epoch and sequence", shared.ErrValidation)
	}
	if b.SchemaVersion < 1 {
		return fmt.Errorf("%w: telemetry event batch schema version must be >= 1", shared.ErrValidation)
	}
	if b.EventTimeMin.IsZero() || b.EventTimeMax.IsZero() || b.EventTimeMax.Before(b.EventTimeMin) {
		return fmt.Errorf("%w: telemetry event batch needs valid signed event-time bounds", shared.ErrValidation)
	}
	for i, e := range b.Events {
		if e.EventID.IsZero() {
			return fmt.Errorf("%w: telemetry event[%d] has no id", shared.ErrValidation, i)
		}
		if !e.Class.Valid() {
			return fmt.Errorf("%w: telemetry event[%d] has an unknown class %q", shared.ErrValidation, i, e.Class)
		}
		if e.Digest == "" {
			return fmt.Errorf("%w: telemetry event[%d] has no digest", shared.ErrValidation, i)
		}
		if len(e.Payload) == 0 {
			return fmt.Errorf("%w: telemetry event[%d] has no payload", shared.ErrValidation, i)
		}
	}
	return nil
}

type TelemetryStreamState struct {
	AgentID    shared.ID
	StreamID   shared.ID
	Epoch      uint64
	Contiguous uint64
	Pending    []uint64
	Version    uint64
	UpdatedAt  time.Time
}

func (s TelemetryStreamState) Validate() error {
	if s.AgentID.IsZero() {
		return fmt.Errorf("%w: telemetry stream state has no agent id", shared.ErrValidation)
	}
	if s.StreamID.IsZero() {
		return fmt.Errorf("%w: telemetry stream state has no stream id", shared.ErrValidation)
	}
	if s.Epoch == 0 {
		return fmt.Errorf("%w: telemetry stream state epoch must be >= 1", shared.ErrValidation)
	}
	for _, seq := range s.Pending {
		if seq <= s.Contiguous {
			return fmt.Errorf("%w: pending sequence %d is not above the contiguous mark %d", shared.ErrValidation, seq, s.Contiguous)
		}
	}
	return nil
}

// TelemetryGap is one durable open delivery-sequence loss window. FromAt..ToAt is conservative observed
// time, allowing a hunt wholly inside the missing interval to remain incomplete even when neither received
// neighboring batch itself falls inside that hunt.
type TelemetryGap struct {
	AgentID      shared.ID
	AssetID      shared.ID
	StreamID     shared.ID
	Priority     fleetagent.DeliveryPriority
	Epoch        uint64
	FromSequence uint64
	ToSequence   uint64
	FromAt       time.Time
	ToAt         time.Time
	DetectedAt   time.Time
}

func (s TelemetryStreamState) LoadAckLedger() *fleetagent.AckLedger {
	ledger := fleetagent.NewAckLedger()
	ledger.SeedContiguous(s.Contiguous)
	for _, seq := range s.Pending {
		ledger.Observe(seq)
	}
	return ledger
}

func (s TelemetryStreamState) GapsFrom() []TelemetryGap {
	ledger := s.LoadAckLedger()
	var gaps []TelemetryGap
	for _, g := range ledger.Gaps() {
		gaps = append(gaps, TelemetryGap{
			AgentID:      s.AgentID,
			StreamID:     s.StreamID,
			Epoch:        s.Epoch,
			FromSequence: g.From,
			ToSequence:   g.To,
		})
	}
	return gaps
}
