package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// CommitBatch atomically claims one delivery coordinate for the exact signed batch
// identity. Concurrent identical replays converge; any equivocation at the same
// (tenant, agent, stream, epoch, sequence) fails closed before ACK classification.
func (r *TelemetryTransportRepository) CommitBatch(ctx context.Context, batch ports.TelemetryEventBatch) error {
	if err := batch.Validate(); err != nil {
		return err
	}
	if err := requireTransportTenant(ctx); err != nil {
		return err
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		tenant, _ := shared.TenantFrom(ctx)
		tag, err := tx.Exec(ctx, `INSERT INTO telemetry_batch_commits
			(tenant_id,agent_id,stream_id,epoch,sequence,batch_id,asset_id,schema_version,payload_digest,event_count)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (tenant_id,agent_id,stream_id,epoch,sequence) DO NOTHING`,
			tenant.String(), batch.AgentID.String(), batch.StreamID.String(), int64(batch.Epoch), int64(batch.Sequence),
			batch.BatchID.String(), batch.AssetID.String(), batch.SchemaVersion, batch.PayloadDigest, len(batch.Events))
		if err != nil {
			return fmt.Errorf("commit telemetry batch identity: %w", err)
		}
		if tag.RowsAffected() == 1 {
			return nil
		}

		var batchID, assetID, payloadDigest string
		var schemaVersion, eventCount int
		if err := tx.QueryRow(ctx, `SELECT batch_id,asset_id,schema_version,payload_digest,event_count
			FROM telemetry_batch_commits
			WHERE tenant_id=$1 AND agent_id=$2 AND stream_id=$3 AND epoch=$4 AND sequence=$5`,
			tenant.String(), batch.AgentID.String(), batch.StreamID.String(), int64(batch.Epoch), int64(batch.Sequence)).
			Scan(&batchID, &assetID, &schemaVersion, &payloadDigest, &eventCount); err != nil {
			return fmt.Errorf("read telemetry batch commitment collision: %w", err)
		}
		if batchID != batch.BatchID.String() || assetID != batch.AssetID.String() ||
			schemaVersion != batch.SchemaVersion || payloadDigest != batch.PayloadDigest || eventCount != len(batch.Events) {
			return fmt.Errorf("%w: telemetry delivery sequence is already committed to a different batch", shared.ErrConflict)
		}
		return nil
	})
}
