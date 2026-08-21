package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.TelemetryDeliveryStore = (*TelemetryRepository)(nil)
var _ ports.TelemetryGapReader = (*TelemetryRepository)(nil)
var _ ports.TelemetryAssetBindingStore = (*TelemetryRepository)(nil)

// IngestDelivery atomically persists the verified A3 batch, its sequence ledger,
// canonical/schema provenance, explicit gap state, and the ACK derived from durable
// sequence rows. No ACK is produced from request receipt alone.
func (r *TelemetryRepository) IngestDelivery(ctx context.Context, batch ports.TelemetryDeliveryBatch) (ports.TelemetryDeliveryResult, error) {
	if err := batch.Validate(); err != nil {
		return ports.TelemetryDeliveryResult{}, err
	}
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() {
		return ports.TelemetryDeliveryResult{}, fmt.Errorf("%w: telemetry delivery requires tenant context", shared.ErrValidation)
	}
	if tenant != batch.TenantID {
		return ports.TelemetryDeliveryResult{}, fmt.Errorf("%w: telemetry delivery tenant disagrees with context", shared.ErrForbidden)
	}
	m := batch.Manifest
	wantStream, err := fleetagent.TelemetryDeliveryStreamID(batch.AgentID, batch.AgentSessionID, m.Priority)
	if err != nil {
		return ports.TelemetryDeliveryResult{}, err
	}
	if wantStream != m.StreamID {
		return ports.TelemetryDeliveryResult{}, fmt.Errorf("%w: telemetry delivery stream is not canonical", shared.ErrValidation)
	}

	var result ports.TelemetryDeliveryResult
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		if err := ensureTelemetryDeliveryStream(ctx, tx, batch); err != nil {
			return err
		}

		currentEpoch, err := lockTelemetryDeliveryStream(ctx, tx, batch)
		if err != nil {
			return err
		}
		allDuplicate, err := preflightTelemetryDeliverySequences(ctx, tx, batch)
		if err != nil {
			return err
		}
		if m.Epoch < currentEpoch && !allDuplicate {
			return fmt.Errorf("%w: telemetry delivery epoch %d is stale; current epoch is %d", shared.ErrConflict, m.Epoch, currentEpoch)
		}
		if m.Epoch > currentEpoch {
			if _, err := tx.Exec(ctx, `UPDATE telemetry_delivery_streams
				SET current_epoch=$1, updated_at=$2 WHERE tenant_id=$3 AND stream_id=$4`,
				int64(m.Epoch), batch.ReceivedAt.UTC(), batch.TenantID.String(), m.StreamID.String()); err != nil {
				return fmt.Errorf("advance telemetry delivery epoch: %w", err)
			}
		}

		if err := insertOrValidateTelemetryBatch(ctx, tx, batch); err != nil {
			return err
		}
		newEvents, err := insertTelemetryDeliveryEvents(ctx, tx, batch)
		if err != nil {
			return err
		}
		ack, ranges, err := telemetryDeliveryACKAndGaps(ctx, tx, batch.TenantID, m.StreamID, m.Epoch)
		if err != nil {
			return err
		}
		if err := reconcilePostgresTelemetryGaps(ctx, tx, batch, ranges); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE telemetry_delivery_batches
			SET state=CASE WHEN sequence <= $1 THEN 'acknowledged' ELSE 'telemetry_durable' END,
			    updated_at=$2
			WHERE tenant_id=$3 AND stream_id=$4 AND epoch=$5`,
			int64(ack), batch.ReceivedAt.UTC(), batch.TenantID.String(), m.StreamID.String(), int64(m.Epoch)); err != nil {
			return fmt.Errorf("advance telemetry batch provenance: %w", err)
		}
		gaps, err := queryTelemetryGapsTx(ctx, tx, telemetryGapQuery{
			tenantID: batch.TenantID, hostID: batch.HostID, assetID: batch.AssetID,
			streamID: m.StreamID, epoch: m.Epoch,
		})
		if err != nil {
			return err
		}
		result = ports.TelemetryDeliveryResult{
			ACK: ports.TelemetryDeliveryACK{Priority: m.Priority, Epoch: m.Epoch, Through: ack},
			NewEvents: newEvents,
			Gaps: gaps,
		}
		return nil
	})
	if err != nil {
		return ports.TelemetryDeliveryResult{}, err
	}
	return result, nil
}

func ensureTelemetryDeliveryStream(ctx context.Context, tx pgx.Tx, batch ports.TelemetryDeliveryBatch) error {
	m := batch.Manifest
	_, err := tx.Exec(ctx, `INSERT INTO telemetry_delivery_streams
		(tenant_id,agent_id,agent_session_id,stream_id,priority,current_epoch,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (tenant_id,stream_id) DO NOTHING`,
		batch.TenantID.String(), batch.AgentID.String(), string(batch.AgentSessionID), m.StreamID.String(), int(m.Priority), int64(m.Epoch), batch.ReceivedAt.UTC())
	if err != nil {
		return fmt.Errorf("create telemetry delivery stream: %w", err)
	}
	return nil
}

func lockTelemetryDeliveryStream(ctx context.Context, tx pgx.Tx, batch ports.TelemetryDeliveryBatch) (uint64, error) {
	m := batch.Manifest
	var agentID, session, streamID string
	var priority int
	var epoch int64
	err := tx.QueryRow(ctx, `SELECT agent_id,agent_session_id,stream_id,priority,current_epoch
		FROM telemetry_delivery_streams WHERE tenant_id=$1 AND stream_id=$2 FOR UPDATE`,
		batch.TenantID.String(), m.StreamID.String()).Scan(&agentID, &session, &streamID, &priority, &epoch)
	if err != nil {
		return 0, fmt.Errorf("lock telemetry delivery stream: %w", err)
	}
	if agentID != batch.AgentID.String() || session != string(batch.AgentSessionID) || streamID != m.StreamID.String() || priority != int(m.Priority) {
		return 0, fmt.Errorf("%w: telemetry delivery stream is bound to different identity", shared.ErrConflict)
	}
	if epoch < 1 {
		return 0, fmt.Errorf("%w: persisted telemetry delivery epoch is invalid", shared.ErrValidation)
	}
	return uint64(epoch), nil
}

func preflightTelemetryDeliverySequences(ctx context.Context, tx pgx.Tx, batch ports.TelemetryDeliveryBatch) (bool, error) {
	m := batch.Manifest
	from := m.PreviousSequence + 1
	allDuplicate := true
	for i := range batch.Envelopes {
		sequence := from + uint64(i)
		key, err := fleetagent.TelemetryDeliveryKey(batch.AgentID, batch.AgentSessionID, m.StreamID, m.Priority, m.Epoch, sequence, 0)
		if err != nil {
			return false, err
		}
		var eventID, digest, storedKey string
		err = tx.QueryRow(ctx, `SELECT event_id,event_digest,delivery_key
			FROM telemetry_delivery_sequences
			WHERE tenant_id=$1 AND stream_id=$2 AND epoch=$3 AND sequence=$4`,
			batch.TenantID.String(), m.StreamID.String(), int64(m.Epoch), int64(sequence)).Scan(&eventID, &digest, &storedKey)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			allDuplicate = false
		case err != nil:
			return false, fmt.Errorf("preflight telemetry delivery sequence: %w", err)
		case eventID != m.EventIDs[i].String() || digest != m.EventDigests[i] || storedKey != key:
			return false, fmt.Errorf("%w: telemetry delivery sequence %d is committed to different content", shared.ErrConflict, sequence)
		}
	}
	return allDuplicate, nil
}

func insertOrValidateTelemetryBatch(ctx context.Context, tx pgx.Tx, batch ports.TelemetryDeliveryBatch) error {
	m := batch.Manifest
	ct, err := tx.Exec(ctx, `INSERT INTO telemetry_delivery_batches
		(tenant_id,batch_id,agent_id,host_id,asset_id,agent_session_id,stream_id,priority,epoch,sequence,previous_sequence,
		 schema_version,key_id,state,payload_digest,event_time_min,event_time_max,received_at,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'received',$14,$15,$16,$17,$17)
		ON CONFLICT (tenant_id,batch_id) DO NOTHING`,
		batch.TenantID.String(), m.BatchID.String(), batch.AgentID.String(), batch.HostID.String(), batch.AssetID.String(),
		string(batch.AgentSessionID), m.StreamID.String(), int(m.Priority), int64(m.Epoch), int64(m.Sequence), int64(m.PreviousSequence),
		m.SchemaVersion, batch.KeyID, m.PayloadDigest, m.EventTimeMin.UTC(), m.EventTimeMax.UTC(), batch.ReceivedAt.UTC())
	if err != nil {
		return fmt.Errorf("insert telemetry delivery batch: %w", err)
	}
	if ct.RowsAffected() == 1 {
		return nil
	}
	var agentID, hostID, assetID, session, streamID, keyID, digest string
	var priority, schemaVersion int
	var epoch, sequence, previous int64
	err = tx.QueryRow(ctx, `SELECT agent_id,host_id,asset_id,agent_session_id,stream_id,priority,epoch,sequence,previous_sequence,schema_version,key_id,payload_digest
		FROM telemetry_delivery_batches WHERE tenant_id=$1 AND batch_id=$2`, batch.TenantID.String(), m.BatchID.String()).Scan(
		&agentID, &hostID, &assetID, &session, &streamID, &priority, &epoch, &sequence, &previous, &schemaVersion, &keyID, &digest)
	if err != nil {
		return fmt.Errorf("read telemetry delivery batch collision: %w", err)
	}
	if agentID != batch.AgentID.String() || hostID != batch.HostID.String() || assetID != batch.AssetID.String() ||
		session != string(batch.AgentSessionID) || streamID != m.StreamID.String() || priority != int(m.Priority) ||
		epoch != int64(m.Epoch) || sequence != int64(m.Sequence) || previous != int64(m.PreviousSequence) ||
		schemaVersion != m.SchemaVersion || keyID != batch.KeyID || digest != m.PayloadDigest {
		return fmt.Errorf("%w: telemetry batch id %q is already bound to different provenance", shared.ErrConflict, m.BatchID)
	}
	return nil
}

func insertTelemetryDeliveryEvents(ctx context.Context, tx pgx.Tx, batch ports.TelemetryDeliveryBatch) (int, error) {
	m := batch.Manifest
	from := m.PreviousSequence + 1
	inserted := 0
	for i := range batch.Envelopes {
		sequence := from + uint64(i)
		key, err := fleetagent.TelemetryDeliveryKey(batch.AgentID, batch.AgentSessionID, m.StreamID, m.Priority, m.Epoch, sequence, 0)
		if err != nil {
			return 0, err
		}
		ct, err := tx.Exec(ctx, `INSERT INTO telemetry_delivery_sequences
			(tenant_id,stream_id,epoch,sequence,event_id,event_digest,delivery_key,batch_id,received_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (tenant_id,stream_id,epoch,sequence) DO NOTHING`,
			batch.TenantID.String(), m.StreamID.String(), int64(m.Epoch), int64(sequence), m.EventIDs[i].String(), m.EventDigests[i], key, m.BatchID.String(), batch.ReceivedAt.UTC())
		if err != nil {
			return 0, fmt.Errorf("insert telemetry delivery sequence: %w", err)
		}
		if ct.RowsAffected() == 0 {
			continue // exact duplicate was proven by preflight.
		}
		projectedJSON, err := json.Marshal(batch.ProjectedEvents[i])
		if err != nil {
			return 0, fmt.Errorf("marshal projected telemetry event: %w", err)
		}
		canonicalJSON, err := json.Marshal(batch.Envelopes[i])
		if err != nil {
			return 0, fmt.Errorf("marshal canonical telemetry envelope: %w", err)
		}
		// seq=0 + idx=NULL intentionally keeps A3 out of the legacy per-class sequence
		// detector. True delivery coordinates live in telemetry_delivery_sequences.
		if _, err := tx.Exec(ctx, `INSERT INTO telemetry_events
			(tenant_id,host_id,asset_id,agent_id,class,seq,idx,sample_rate,event,observed_at,tier,
			 schema_version,agent_session_id,delivery_stream_id,delivery_priority,epoch,batch_id,event_id,canonical_event,delivery_key,received_at)
			VALUES ($1,$2,$3,$4,$5,0,NULL,1,$6,$7,'hot',$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
			ON CONFLICT (tenant_id,delivery_key) WHERE delivery_key IS NOT NULL DO NOTHING`,
			batch.TenantID.String(), batch.HostID.String(), batch.AssetID.String(), batch.AgentID.String(), string(batch.Envelopes[i].EventClass),
			projectedJSON, batch.Envelopes[i].OccurredAt.UTC(), m.SchemaVersion, string(batch.AgentSessionID), m.StreamID.String(), int(m.Priority),
			int64(m.Epoch), m.BatchID.String(), m.EventIDs[i].String(), canonicalJSON, key, batch.ReceivedAt.UTC()); err != nil {
			return 0, fmt.Errorf("insert A3 telemetry event: %w", err)
		}
		inserted++
	}
	return inserted, nil
}

func telemetryDeliveryACKAndGaps(ctx context.Context, tx pgx.Tx, tenantID shared.ID, streamID shared.ID, epoch uint64) (uint64, []fleetagent.SeqRange, error) {
	rows, err := tx.Query(ctx, `SELECT sequence FROM telemetry_delivery_sequences
		WHERE tenant_id=$1 AND stream_id=$2 AND epoch=$3 ORDER BY sequence`, tenantID.String(), streamID.String(), int64(epoch))
	if err != nil {
		return 0, nil, fmt.Errorf("query telemetry delivery sequences: %w", err)
	}
	defer rows.Close()
	var sequences []uint64
	for rows.Next() {
		var seq int64
		if err := rows.Scan(&seq); err != nil {
			return 0, nil, err
		}
		if seq < 1 {
			return 0, nil, fmt.Errorf("%w: persisted delivery sequence is invalid", shared.ErrValidation)
		}
		sequences = append(sequences, uint64(seq))
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	var (
		ack      uint64
		previous uint64
		ranges   []fleetagent.SeqRange
	)
	for _, seq := range sequences {
		if seq > previous+1 {
			ranges = append(ranges, fleetagent.SeqRange{From: previous + 1, To: seq - 1})
		}
		previous = seq
	}
	if len(ranges) == 0 {
		ack = previous
	} else if ranges[0].From > 1 {
		ack = ranges[0].From - 1
	}
	return ack, ranges, nil
}

func reconcilePostgresTelemetryGaps(ctx context.Context, tx pgx.Tx, batch ports.TelemetryDeliveryBatch, wanted []fleetagent.SeqRange) error {
	m := batch.Manifest
	type gapKey struct{ from, to uint64 }
	remaining := make(map[gapKey]fleetagent.SeqRange, len(wanted))
	for _, rg := range wanted {
		remaining[gapKey{rg.From, rg.To}] = rg
	}
	rows, err := tx.Query(ctx, `SELECT from_sequence,to_sequence FROM telemetry_gaps
		WHERE tenant_id=$1 AND stream_id=$2 AND epoch=$3 AND resolved_at IS NULL FOR UPDATE`,
		batch.TenantID.String(), m.StreamID.String(), int64(m.Epoch))
	if err != nil {
		return fmt.Errorf("query unresolved telemetry gaps: %w", err)
	}
	var existing []gapKey
	for rows.Next() {
		var from, to int64
		if err := rows.Scan(&from, &to); err != nil {
			rows.Close()
			return err
		}
		existing = append(existing, gapKey{uint64(from), uint64(to)})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, key := range existing {
		if _, ok := remaining[key]; ok {
			delete(remaining, key)
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE telemetry_gaps SET resolved_at=$1
			WHERE tenant_id=$2 AND stream_id=$3 AND epoch=$4 AND from_sequence=$5 AND to_sequence=$6 AND resolved_at IS NULL`,
			batch.ReceivedAt.UTC(), batch.TenantID.String(), m.StreamID.String(), int64(m.Epoch), int64(key.from), int64(key.to)); err != nil {
			return fmt.Errorf("resolve telemetry gap: %w", err)
		}
	}
	for _, rg := range remaining {
		// Exact missing event times are unknowable by definition. Anchor the uncertainty
		// to the first event time that proved the hole; hunt matching is therefore
		// conservative around the observed break without fabricating timestamps.
		if _, err := tx.Exec(ctx, `INSERT INTO telemetry_gaps
			(tenant_id,host_id,asset_id,agent_id,agent_session_id,stream_id,priority,epoch,from_sequence,to_sequence,from_at,to_at,detected_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11,$12)
			ON CONFLICT (tenant_id,stream_id,epoch,from_sequence,to_sequence) WHERE resolved_at IS NULL DO NOTHING`,
			batch.TenantID.String(), batch.HostID.String(), batch.AssetID.String(), batch.AgentID.String(), string(batch.AgentSessionID),
			m.StreamID.String(), int(m.Priority), int64(m.Epoch), int64(rg.From), int64(rg.To), m.EventTimeMin.UTC(), batch.ReceivedAt.UTC()); err != nil {
			return fmt.Errorf("persist telemetry gap: %w", err)
		}
	}
	return nil
}

type telemetryGapQuery struct {
	tenantID shared.ID
	hostID   shared.ID
	assetID  shared.ID
	streamID shared.ID
	priority *fleetagent.DeliveryPriority
	epoch    uint64
	since    time.Time
	until    time.Time
}

func queryTelemetryGapsTx(ctx context.Context, tx pgx.Tx, q telemetryGapQuery) ([]ports.TelemetryGap, error) {
	rows, err := tx.Query(ctx, `SELECT tenant_id,host_id,asset_id,agent_id,agent_session_id,stream_id,priority,epoch,
		from_sequence,to_sequence,from_at,to_at,detected_at,resolved_at
		FROM telemetry_gaps
		WHERE tenant_id=$1
		  AND ($2='' OR host_id=$2)
		  AND ($3='' OR asset_id=$3)
		  AND ($4='' OR stream_id=$4)
		  AND ($5::smallint IS NULL OR priority=$5)
		  AND ($6::bigint=0 OR epoch=$6)
		  AND ($7::timestamptz IS NULL OR to_at >= $7)
		  AND ($8::timestamptz IS NULL OR from_at <= $8)
		  AND resolved_at IS NULL
		ORDER BY epoch,from_sequence`,
		q.tenantID.String(), q.hostID.String(), q.assetID.String(), q.streamID.String(), nullablePriority(q.priority), int64(q.epoch), nullableTime(q.since), nullableTime(q.until))
	if err != nil {
		return nil, fmt.Errorf("query telemetry gaps: %w", err)
	}
	defer rows.Close()
	var out []ports.TelemetryGap
	for rows.Next() {
		var (
			g                                             ports.TelemetryGap
			tenant, host, asset, agent, session, stream string
			priority                                      int
			epoch, from, to                                int64
		)
		if err := rows.Scan(&tenant, &host, &asset, &agent, &session, &stream, &priority, &epoch, &from, &to,
			&g.FromAt, &g.ToAt, &g.DetectedAt, &g.ResolvedAt); err != nil {
			return nil, err
		}
		g.TenantID, g.HostID, g.AssetID, g.AgentID = shared.ID(tenant), shared.ID(host), shared.ID(asset), shared.ID(agent)
		g.AgentSessionID, g.StreamID = fleetagent.SessionID(session), shared.ID(stream)
		g.Priority, g.Epoch, g.FromSequence, g.ToSequence = fleetagent.DeliveryPriority(priority), uint64(epoch), uint64(from), uint64(to)
		out = append(out, g)
	}
	return out, rows.Err()
}

func nullablePriority(priority *fleetagent.DeliveryPriority) any {
	if priority == nil {
		return nil
	}
	return int(*priority)
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

// QueryDeliveryGaps returns current first-class transport holes intersecting a
// retro-hunt. A priority lane can carry more than one event class, so a class query
// conservatively considers a gap in its lane incomplete: the missing record's class is
// unknowable until it arrives.
func (r *TelemetryRepository) QueryDeliveryGaps(ctx context.Context, q ports.HuntQuery) ([]ports.TelemetryGap, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() {
		return nil, fmt.Errorf("%w: telemetry gap query requires tenant context", shared.ErrValidation)
	}
	var priority *fleetagent.DeliveryPriority
	if q.Class != "" {
		p, err := fleetagent.TelemetryPriority(q.Class)
		if err != nil {
			return nil, err
		}
		priority = &p
	}
	var out []ports.TelemetryGap
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		var err error
		out, err = queryTelemetryGapsTx(ctx, tx, telemetryGapQuery{
			tenantID: tenant, hostID: q.HostID, assetID: q.AssetID, priority: priority,
			since: q.Since, until: q.Until,
		})
		return err
	})
	return out, err
}

// BindTelemetryAsset persists the inventory reconciliation result. The request body
// never calls this method; only the authenticated host-inventory path may establish it.
func (r *TelemetryRepository) BindTelemetryAsset(ctx context.Context, binding ports.TelemetryAssetBinding) error {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() {
		return fmt.Errorf("%w: telemetry asset binding requires tenant context", shared.ErrValidation)
	}
	if binding.TenantID.IsZero() || binding.AgentID.IsZero() || binding.AssetID.IsZero() || binding.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: telemetry asset binding is incomplete", shared.ErrValidation)
	}
	if binding.TenantID != tenant {
		return fmt.Errorf("%w: telemetry asset binding tenant disagrees with context", shared.ErrForbidden)
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `INSERT INTO telemetry_asset_bindings (tenant_id,agent_id,asset_id,updated_at)
			VALUES ($1,$2,$3,$4)
			ON CONFLICT (tenant_id,agent_id) DO UPDATE
			SET asset_id=EXCLUDED.asset_id, updated_at=EXCLUDED.updated_at
			WHERE telemetry_asset_bindings.updated_at <= EXCLUDED.updated_at`,
			binding.TenantID.String(), binding.AgentID.String(), binding.AssetID.String(), binding.UpdatedAt.UTC())
		if err != nil {
			return fmt.Errorf("bind telemetry asset: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return fmt.Errorf("%w: stale telemetry asset binding update", shared.ErrConflict)
		}
		return nil
	})
}

func (r *TelemetryRepository) ResolveTelemetryAsset(ctx context.Context, agentID shared.ID) (shared.ID, error) {
	if agentID.IsZero() {
		return "", fmt.Errorf("%w: telemetry asset resolution requires agent id", shared.ErrValidation)
	}
	var asset string
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT asset_id FROM telemetry_asset_bindings WHERE agent_id=$1`, agentID.String()).Scan(&asset)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", shared.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("resolve telemetry asset: %w", err)
	}
	return shared.ID(asset), nil
}

// keep sort imported for deterministic future range helpers; currently query order is SQL-defined.
var _ = sort.Slice
