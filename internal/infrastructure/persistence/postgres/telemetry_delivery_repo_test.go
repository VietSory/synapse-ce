package postgres

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	dtelemetry "github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func postgresDeliveryBatchFor(t *testing.T, tenant, agent, asset shared.ID, epoch, previous uint64, count int, suffix string) ports.TelemetryDeliveryBatch {
	t.Helper()
	session := fleetagent.CanonicalSessionID(agent)
	stream, err := fleetagent.TelemetryDeliveryStreamID(agent, session, fleetagent.PriorityP3)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 22, 0, 0, 0, 0, time.UTC)
	envelopes := make([]dtelemetry.TelemetryEnvelope, count)
	projected := make([]detection.Event, count)
	ids := make([]shared.ID, count)
	digests := make([]string, count)
	for i := 0; i < count; i++ {
		seq := previous + uint64(i) + 1
		id := shared.ID(fmt.Sprintf("event-%d-%s", seq, suffix))
		ids[i] = id
		digests[i] = fleetagent.SHA256Hex([]byte(id))
		obs := &dtelemetry.ProcessObservation{
			Kind:     "exec",
			PID:      int(seq) + 10,
			EntityID: shared.ID(fmt.Sprintf("pe-%d-%s", seq, suffix)),
			Comm:     "sh",
			Path:     "/bin/sh",
		}
		event := dtelemetry.TelemetryEvent{Class: detection.ClassProcess, Process: obs}
		envelopes[i] = dtelemetry.TelemetryEnvelope{
			SchemaVersion: 1,
			EventID:       id,
			EventType:     event.EventType(),
			EventClass:    detection.ClassProcess,
			AgentID:       agent,
			AssetID:       asset,
			OccurredAt:    at.Add(time.Duration(seq) * time.Second),
			ObservedAt:    at.Add(time.Duration(seq) * time.Second),
			ReceivedAt:    at.Add(time.Minute),
			Event:         event,
		}
		projected[i] = detection.Event{
			Class: detection.ClassProcess,
			At:    envelopes[i].OccurredAt,
			Host:  agent,
			Process: &detection.ProcessEvent{
				PID:  obs.PID,
				Comm: obs.Comm,
				Path: obs.Path,
			},
		}
	}
	sequence := previous + uint64(count)
	payloadDigest := fleetagent.SHA256Hex([]byte(fmt.Sprintf("payload-%d-%d-%s", epoch, sequence, suffix)))
	manifest := fleetagent.TelemetryBatchManifest{
		ProtocolVersion:      1,
		SchemaVersion:        1,
		BatchID:              fleetagent.DeriveTelemetryBatchID(agent, session, stream, epoch, sequence, payloadDigest),
		AgentID:              agent,
		HostID:               agent,
		AgentSessionID:       session,
		AssetID:              asset,
		StreamID:             stream,
		Priority:             fleetagent.PriorityP3,
		Epoch:                epoch,
		Sequence:             sequence,
		PreviousSequence:     previous,
		EventTimeMin:         envelopes[0].OccurredAt,
		EventTimeMax:         envelopes[len(envelopes)-1].OccurredAt,
		ObservedCount:        uint64(count),
		KeptCount:            uint64(count),
		SamplingPolicyDigest: fleetagent.SHA256Hex([]byte("keep-all")),
		EventIDs:             ids,
		EventDigests:         digests,
		PayloadDigest:        payloadDigest,
	}
	return ports.TelemetryDeliveryBatch{
		TenantID:        tenant,
		HostID:          agent,
		AssetID:         asset,
		AgentID:         agent,
		AgentSessionID:  session,
		Manifest:        manifest,
		KeyID:           "key-a",
		Envelopes:       envelopes,
		ProjectedEvents: projected,
		ReceivedAt:      at.Add(time.Minute),
	}
}

func TestPostgresTelemetryDeliveryConvergesAcrossReplayGapLateFillAndEpochReset(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	id := randHex(t)
	tenantA := shared.ID("td-a-" + id)
	tenantB := shared.ID("td-b-" + id)
	agent := shared.ID("agent-" + id)
	asset := shared.ID("asset-" + id)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, tenantA.String(), tenantB.String()); err != nil {
		t.Fatalf("seed tenants: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fleet_assets(id,tenant_id,kind,"key",name) VALUES($1,$2,'host',$1,$1)`, asset.String(), tenantA.String()); err != nil {
		t.Fatalf("seed canonical asset: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fleet_agents(id,tenant_id,name,token_hash,state) VALUES($1,$2,$1,$3,'active')`, agent.String(), tenantA.String(), "test-token-"+id); err != nil {
		t.Fatalf("seed fleet agent: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_events WHERE tenant_id=$1`, tenantA.String())
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_gaps WHERE tenant_id=$1`, tenantA.String())
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_delivery_batches WHERE tenant_id=$1`, tenantA.String())
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_delivery_sequences WHERE tenant_id=$1`, tenantA.String())
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_delivery_streams WHERE tenant_id=$1`, tenantA.String())
		_, _ = pool.Exec(bg, `DELETE FROM fleet_agents WHERE tenant_id=$1`, tenantA.String())
		_, _ = pool.Exec(bg, `DELETE FROM fleet_assets WHERE tenant_id=$1`, tenantA.String())
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id IN ($1,$2)`, tenantA.String(), tenantB.String())
	})

	repo := NewTelemetryRepository(pool, time.Hour, 24*time.Hour)
	tctxA := shared.WithTenant(ctx, tenantA)

	first := postgresDeliveryBatchFor(t, tenantA, agent, asset, 1, 0, 1, "one")
	got, err := repo.IngestDelivery(tctxA, first)
	if err != nil {
		t.Fatalf("sequence 1: %v", err)
	}
	if got.ACK.Epoch != 1 || got.ACK.Through != 1 || got.NewEvents != 1 || len(got.Gaps) != 0 {
		t.Fatalf("sequence 1 result = %+v", got)
	}

	replay, err := repo.IngestDelivery(tctxA, first)
	if err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	if replay.ACK.Through != 1 || replay.NewEvents != 0 || len(replay.Gaps) != 0 {
		t.Fatalf("replay result = %+v", replay)
	}

	ahead := postgresDeliveryBatchFor(t, tenantA, agent, asset, 1, 2, 1, "three")
	got, err = repo.IngestDelivery(tctxA, ahead)
	if err != nil {
		t.Fatalf("sequence 3: %v", err)
	}
	if got.ACK.Through != 1 || len(got.Gaps) != 1 || got.Gaps[0].FromSequence != 2 || got.Gaps[0].ToSequence != 2 {
		t.Fatalf("gap result = %+v", got)
	}

	fill := postgresDeliveryBatchFor(t, tenantA, agent, asset, 1, 1, 1, "two")
	got, err = repo.IngestDelivery(tctxA, fill)
	if err != nil {
		t.Fatalf("late fill sequence 2: %v", err)
	}
	if got.ACK.Through != 3 || len(got.Gaps) != 0 {
		t.Fatalf("late fill result = %+v", got)
	}
	q := ports.HuntQuery{
		HostID: agent,
		Class:  detection.ClassProcess,
		Since:  first.Manifest.EventTimeMin.Add(-time.Minute),
		Until:  ahead.Manifest.EventTimeMax.Add(time.Minute),
	}
	gaps, err := repo.QueryDeliveryGaps(tctxA, q)
	if err != nil || len(gaps) != 0 {
		t.Fatalf("resolved gaps = %+v err=%v", gaps, err)
	}

	reboot := postgresDeliveryBatchFor(t, tenantA, agent, asset, 2, 0, 1, "reboot")
	got, err = repo.IngestDelivery(tctxA, reboot)
	if err != nil {
		t.Fatalf("epoch reset: %v", err)
	}
	if got.ACK.Epoch != 2 || got.ACK.Through != 1 || got.NewEvents != 1 || len(got.Gaps) != 0 {
		t.Fatalf("epoch reset result = %+v", got)
	}

	// Prove the migration's tenant policies with a real NOSUPERUSER/NOBYPASSRLS role instead of
	// relying on repository WHERE clauses while the CI pool runs as a postgres superuser.
	role := "td_runtime_" + id
	for _, statement := range []string{
		`CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT ON telemetry_delivery_sequences TO ` + role,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatalf("prepare telemetry RLS role: %v", err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DROP OWNED BY `+role)
		_, _ = pool.Exec(bg, `DROP ROLE IF EXISTS `+role)
	})
	countAs := func(tenant shared.ID) int {
		t.Helper()
		var n int
		tenantCtx := shared.WithTenant(context.Background(), tenant)
		if err := WithTenant(tenantCtx, pool, tenant.String(), func(tx pgx.Tx) error {
			if _, err := tx.Exec(tenantCtx, `SET LOCAL ROLE `+role); err != nil {
				return err
			}
			return tx.QueryRow(tenantCtx, `SELECT count(*) FROM telemetry_delivery_sequences`).Scan(&n)
		}); err != nil {
			t.Fatalf("count delivery sequences as %s: %v", tenant, err)
		}
		return n
	}
	if got := countAs(tenantB); got != 0 {
		t.Fatalf("tenant B sees %d tenant A delivery sequences; RLS isolation failed", got)
	}
	if got := countAs(tenantA); got != 4 {
		t.Fatalf("tenant A sees %d delivery sequences, want 4 across two epochs", got)
	}
}
