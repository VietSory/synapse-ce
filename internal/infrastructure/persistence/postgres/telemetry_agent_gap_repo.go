package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type TelemetryAgentGapRepository struct{ pool *pgxpool.Pool }

func NewTelemetryAgentGapRepository(pool *pgxpool.Pool) *TelemetryAgentGapRepository {
	return &TelemetryAgentGapRepository{pool: pool}
}

func (r *TelemetryAgentGapRepository) IngestAgentGap(ctx context.Context, gap ports.TelemetryAgentGap) error {
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
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		from, to := nullableAgentGapRange(gap)
		ct, err := tx.Exec(ctx, `INSERT INTO telemetry_agent_gaps
			(tenant_id,gap_id,host_id,asset_id,agent_id,agent_session_id,stream_id,priority,epoch,
			 known_sequence,from_sequence,to_sequence,reason,count,occurred_at,received_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
			ON CONFLICT (tenant_id,agent_id,gap_id) DO NOTHING`,
			gap.TenantID.String(), gap.GapID.String(), gap.HostID.String(), gap.AssetID.String(), gap.AgentID.String(),
			string(gap.AgentSessionID), gap.StreamID.String(), int(gap.Priority), int64(gap.Epoch), gap.KnownSequence,
			from, to, gap.Reason, int64(gap.Count), gap.OccurredAt.UTC(), gap.ReceivedAt.UTC())
		if err != nil {
			return fmt.Errorf("insert telemetry agent gap: %w", err)
		}
		if ct.RowsAffected() == 1 {
			return nil
		}
		existing, err := scanTelemetryAgentGap(tx.QueryRow(ctx, `SELECT tenant_id,gap_id,host_id,asset_id,agent_id,agent_session_id,
			stream_id,priority,epoch,known_sequence,from_sequence,to_sequence,reason,count,occurred_at,received_at
			FROM telemetry_agent_gaps WHERE agent_id=$1 AND gap_id=$2 FOR UPDATE`, gap.AgentID.String(), gap.GapID.String()))
		if err != nil {
			return fmt.Errorf("read telemetry agent gap collision: %w", err)
		}
		if existing.SameEvidence(gap) {
			return nil
		}
		if !gap.MonotonicExtensionOf(existing) {
			return fmt.Errorf("%w: telemetry agent gap id %q is already bound to incompatible evidence", shared.ErrConflict, gap.GapID)
		}
		if _, err := tx.Exec(ctx, `UPDATE telemetry_agent_gaps
			SET from_sequence=$1,to_sequence=$2,count=$3
			WHERE agent_id=$4 AND gap_id=$5`, from, to, int64(gap.Count), gap.AgentID.String(), gap.GapID.String()); err != nil {
			return fmt.Errorf("advance telemetry agent gap evidence: %w", err)
		}
		return nil
	})
}

func (r *TelemetryAgentGapRepository) QueryAgentGaps(ctx context.Context, q ports.HuntQuery) ([]ports.TelemetryAgentGap, error) {
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
	var out []ports.TelemetryAgentGap
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id,gap_id,host_id,asset_id,agent_id,agent_session_id,
			stream_id,priority,epoch,known_sequence,from_sequence,to_sequence,reason,count,occurred_at,received_at
			FROM telemetry_agent_gaps
			WHERE ($1='' OR host_id=$1) AND ($2='' OR asset_id=$2)
			  AND ($3::smallint IS NULL OR priority=$3)
			  AND ($4::timestamptz IS NULL OR occurred_at >= $4)
			  AND ($5::timestamptz IS NULL OR occurred_at <= $5)
			ORDER BY occurred_at,gap_id`, q.HostID.String(), q.AssetID.String(), nullableTelemetryPriority(priority),
			nullableTelemetryGapTime(q.Since), nullableTelemetryGapTime(q.Until))
		if err != nil {
			return fmt.Errorf("query telemetry agent gaps: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			gap, err := scanTelemetryAgentGap(rows)
			if err != nil {
				return err
			}
			out = append(out, gap)
		}
		return rows.Err()
	})
	return out, err
}

func scanTelemetryAgentGap(row rowScanner) (ports.TelemetryAgentGap, error) {
	var g ports.TelemetryAgentGap
	var tenant, gapID, host, asset, agent, session, stream string
	var priority int
	var epoch, count int64
	var from, to *int64
	if err := row.Scan(&tenant, &gapID, &host, &asset, &agent, &session, &stream, &priority, &epoch,
		&g.KnownSequence, &from, &to, &g.Reason, &count, &g.OccurredAt, &g.ReceivedAt); err != nil {
		return g, err
	}
	g.TenantID, g.GapID, g.HostID, g.AssetID, g.AgentID = shared.ID(tenant), shared.ID(gapID), shared.ID(host), shared.ID(asset), shared.ID(agent)
	g.AgentSessionID, g.StreamID = fleetagent.SessionID(session), shared.ID(stream)
	g.Priority, g.Epoch, g.Count = fleetagent.DeliveryPriority(priority), uint64(epoch), uint64(count)
	if from != nil {
		g.FromSequence = uint64(*from)
	}
	if to != nil {
		g.ToSequence = uint64(*to)
	}
	if err := g.Validate(); err != nil {
		return ports.TelemetryAgentGap{}, fmt.Errorf("stored telemetry agent gap is corrupt: %w", err)
	}
	return g, nil
}

func nullableAgentGapRange(g ports.TelemetryAgentGap) (any, any) {
	if !g.KnownSequence {
		return nil, nil
	}
	return int64(g.FromSequence), int64(g.ToSequence)
}

var _ ports.TelemetryAgentGapStore = (*TelemetryAgentGapRepository)(nil)
