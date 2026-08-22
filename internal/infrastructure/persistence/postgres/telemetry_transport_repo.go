package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TelemetryTransportRepository composes the existing event/delivery repository
// with durable agent-origin loss. Delivery ingest remains idempotent in the base
// transaction; a second stream-locked projection may only advance provenance and
// ACK after known-coordinate loss evidence is already durable.
type TelemetryTransportRepository struct {
	*TelemetryRepository
	agentGaps *TelemetryAgentGapRepository
}

func NewTelemetryTransportRepository(pool *pgxpool.Pool, hot, warm time.Duration) *TelemetryTransportRepository {
	return &TelemetryTransportRepository{
		TelemetryRepository: NewTelemetryRepository(pool, hot, warm),
		agentGaps:           NewTelemetryAgentGapRepository(pool),
	}
}

func (r *TelemetryTransportRepository) IngestAgentGap(ctx context.Context, gap ports.TelemetryAgentGap) error {
	return r.agentGaps.IngestAgentGap(ctx, gap)
}

func (r *TelemetryTransportRepository) QueryAgentGaps(ctx context.Context, q ports.HuntQuery) ([]ports.TelemetryAgentGap, error) {
	return r.agentGaps.QueryAgentGaps(ctx, q)
}

func (r *TelemetryTransportRepository) IngestDelivery(ctx context.Context, batch ports.TelemetryDeliveryBatch) (ports.TelemetryDeliveryResult, error) {
	result, err := r.TelemetryRepository.IngestDelivery(ctx, batch)
	if err != nil {
		return ports.TelemetryDeliveryResult{}, err
	}
	ack, err := r.projectDurableOutcomeACK(ctx, batch)
	if err != nil {
		// The base delivery is already durable. Failing the request is intentional:
		// the agent retains WAL and an idempotent retry can repair ACK projection.
		return ports.TelemetryDeliveryResult{}, err
	}
	if ack > result.ACK.Through {
		result.ACK.Through = ack
	}
	return result, nil
}

func (r *TelemetryTransportRepository) projectDurableOutcomeACK(ctx context.Context, batch ports.TelemetryDeliveryBatch) (uint64, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() {
		return 0, fmt.Errorf("%w: telemetry ACK projection requires tenant context", shared.ErrValidation)
	}
	if tenant != batch.TenantID {
		return 0, fmt.Errorf("%w: telemetry ACK projection tenant disagrees with delivery", shared.ErrForbidden)
	}
	m := batch.Manifest
	var ack uint64
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		// Serialize this projection with ordinary delivery ingest for the same stream.
		// Agent-gap ingest may commit concurrently; missing a just-committed gap only
		// delays ACK until the next idempotent retry and can never produce a false ACK.
		var lockedStream string
		if err := tx.QueryRow(ctx, `SELECT stream_id FROM telemetry_delivery_streams
			WHERE tenant_id=$1 AND stream_id=$2 FOR UPDATE`, tenant.String(), m.StreamID.String()).Scan(&lockedStream); err != nil {
			return fmt.Errorf("lock telemetry stream for durable-outcome ACK: %w", err)
		}

		deliveredRows, err := tx.Query(ctx, `SELECT sequence FROM telemetry_delivery_sequences
			WHERE tenant_id=$1 AND stream_id=$2 AND epoch=$3 ORDER BY sequence`, tenant.String(), m.StreamID.String(), int64(m.Epoch))
		if err != nil {
			return fmt.Errorf("query delivered telemetry coordinates for ACK: %w", err)
		}
		delivered := make([]uint64, 0)
		for deliveredRows.Next() {
			var sequence int64
			if err := deliveredRows.Scan(&sequence); err != nil {
				deliveredRows.Close()
				return err
			}
			if sequence < 1 {
				deliveredRows.Close()
				return fmt.Errorf("%w: persisted telemetry delivery sequence is invalid", shared.ErrValidation)
			}
			delivered = append(delivered, uint64(sequence))
		}
		if err := deliveredRows.Err(); err != nil {
			deliveredRows.Close()
			return err
		}
		deliveredRows.Close()

		lossRows, err := tx.Query(ctx, `SELECT from_sequence,to_sequence FROM telemetry_agent_gaps
			WHERE tenant_id=$1 AND stream_id=$2 AND epoch=$3 AND known_sequence
			ORDER BY from_sequence,to_sequence`, tenant.String(), m.StreamID.String(), int64(m.Epoch))
		if err != nil {
			return fmt.Errorf("query durable telemetry loss coordinates for ACK: %w", err)
		}
		losses := make([]fleetagent.SeqRange, 0)
		for lossRows.Next() {
			var from, to int64
			if err := lossRows.Scan(&from, &to); err != nil {
				lossRows.Close()
				return err
			}
			if from < 1 || to < from {
				lossRows.Close()
				return fmt.Errorf("%w: persisted known telemetry loss range is invalid", shared.ErrValidation)
			}
			losses = append(losses, fleetagent.SeqRange{From: uint64(from), To: uint64(to)})
		}
		if err := lossRows.Err(); err != nil {
			lossRows.Close()
			return err
		}
		lossRows.Close()

		ack, err = fleetagent.HighestContiguousDurableOutcome(delivered, losses)
		if err != nil {
			return fmt.Errorf("compute telemetry durable-outcome ACK: %w", err)
		}
		if ack == 0 {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE telemetry_delivery_batches
			SET state='acknowledged', updated_at=GREATEST(updated_at,$1)
			WHERE tenant_id=$2 AND stream_id=$3 AND epoch=$4 AND sequence <= $5`,
			batch.ReceivedAt.UTC(), tenant.String(), m.StreamID.String(), int64(m.Epoch), int64(ack)); err != nil {
			return fmt.Errorf("advance telemetry batch provenance across durable loss: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return ack, nil
}

var _ ports.TelemetryDeliveryStore = (*TelemetryTransportRepository)(nil)
var _ ports.TelemetryAgentGapStore = (*TelemetryTransportRepository)(nil)
var _ ports.TelemetryStore = (*TelemetryTransportRepository)(nil)
var _ ports.TelemetryGapReader = (*TelemetryTransportRepository)(nil)
var _ ports.TelemetryAssetBindingStore = (*TelemetryTransportRepository)(nil)
