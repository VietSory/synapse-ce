package ports

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TelemetryTransportStore persists the AGENT→CONTROL-PLANE transport sequencing state (A3, #624), kept
// deliberately separate from the columnar TelemetryStore: it holds per-stream delivery bookkeeping
// (the highest-contiguous ACK snapshot) keyed by the incarnation-aware (AgentID, StreamID, Epoch), which
// the columnar (host, class, sequence) store does not model. It is the durable home for the A0.4 AckLedger.
// Every method is keyed by the AUTHENTICATED agent id (never an agent-chosen wire field) and tenant-scoped
// from the ctx.
type TelemetryTransportStore interface {
	StreamState(ctx context.Context, agentID, streamID shared.ID, epoch uint64) (TelemetryStreamState, error)
	SaveStreamState(ctx context.Context, state TelemetryStreamState) error
	MaxEpoch(ctx context.Context, agentID, streamID shared.ID) (uint64, error)
	ListGaps(ctx context.Context, agentID, streamID shared.ID) ([]TelemetryGap, error)
	// CommitBatch durably claims one delivery coordinate for the exact signed batch identity before the
	// use case decides whether the sequence is fresh or a replay. The same commitment is idempotent; a
	// different BatchID/PayloadDigest/schema/asset/event-count at the same coordinate is ErrConflict.
	CommitBatch(ctx context.Context, batch TelemetryEventBatch) error
	// IngestBatchEvents persists the raw events after CommitBatch has fixed the sequence commitment.
	// Re-delivery of identical event coordinates is a no-op; conflicting event content is ErrConflict.
	IngestBatchEvents(ctx context.Context, batch TelemetryEventBatch) (int, error)
	CountBatchEvents(ctx context.Context, agentID, streamID shared.ID, epoch, sequence uint64) (int, error)
}

// TelemetryEventBatch is one accepted batch's durable transport commitment plus its raw events, already
// verified against the signed manifest (identity, key, schema, per-event digest) by the ingest usecase.
type TelemetryEventBatch struct {
	BatchID       shared.ID
	PayloadDigest string
	AgentID       shared.ID
	StreamID      shared.ID
	AssetID       shared.ID
	Epoch         uint64
	Sequence      uint64
	SchemaVersion int
	Events        []StoredTelemetryEvent
}

// StoredTelemetryEvent is one raw telemetry event persisted by the transport store: its stable id, class,
// content digest (matched against the manifest), opaque shipped bytes, and source time.
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
	if b.Epoch == 0 || b.Sequence == 0 {
		return fmt.Errorf("%w: telemetry event batch needs a non-zero epoch and sequence", shared.ErrValidation)
	}
	if b.SchemaVersion < 1 {
		return fmt.Errorf("%w: telemetry event batch schema version must be >= 1", shared.ErrValidation)
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

// TelemetryStreamState is the durable AckLedger snapshot for one (AgentID, StreamID, Epoch): the highest
// sequence with no hole beneath it (the ACK returned to the agent so it can delete acked batches), plus the
// received sequences ABOVE the contiguous mark that are waiting for their gap to fill. Version is the
// optimistic-concurrency token used by SaveStreamState.
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

// TelemetryGap is a durable, queryable missing delivery-sequence range. The current open set is reconciled
// from the ACK snapshot; resolved rows may remain in persistent history.
type TelemetryGap struct {
	AgentID      shared.ID
	StreamID     shared.ID
	Epoch        uint64
	FromSequence uint64
	ToSequence   uint64
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
