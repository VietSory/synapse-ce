package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func postgresAgentGapFor(batch ports.TelemetryDeliveryBatch, id shared.ID, known bool) ports.TelemetryAgentGap {
	gap := ports.TelemetryAgentGap{
		TenantID: batch.TenantID, HostID: batch.HostID, AssetID: batch.AssetID, AgentID: batch.AgentID,
		AgentSessionID: batch.AgentSessionID, StreamID: batch.Manifest.StreamID,
		Priority: batch.Manifest.Priority, Epoch: batch.Manifest.Epoch, GapID: id,
		KnownSequence: known, Reason: string(ports.SpoolGapQuotaEviction), Count: 2,
		OccurredAt: batch.Manifest.EventTimeMin.Add(-2 * time.Second), ReceivedAt: batch.ReceivedAt.Add(-time.Second),
	}
	if known {
		gap.FromSequence = 1
		gap.ToSequence = 2
	}
	return gap
}

func TestPostgresTelemetryTransportACKAdvancesOnlyAcrossDurableKnownLoss(t *testing.T) {
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
	tenant := shared.ID("tout-" + id)
	agent := shared.ID("tout-agent-" + id)
	asset := shared.ID("tout-asset-" + id)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fleet_assets(id,tenant_id,kind,"key",name) VALUES($1,$2,'host',$1,$1)`, asset.String(), tenant.String()); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fleet_agents(id,tenant_id,name,token_hash,state) VALUES($1,$2,$1,$3,'active')`, agent.String(), tenant.String(), "tout-token-"+id); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_events WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_gaps WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_agent_gaps WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_delivery_batches WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_delivery_sequences WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_delivery_streams WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM fleet_agents WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM fleet_assets WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id=$1`, tenant.String())
	})

	repo := NewTelemetryTransportRepository(pool, time.Hour, 24*time.Hour)
	tctx := shared.WithTenant(ctx, tenant)

	knownBatch := postgresDeliveryBatchFor(t, tenant, agent, asset, 1, 2, 1, "known-outcome")
	if err := repo.IngestAgentGap(tctx, postgresAgentGapFor(knownBatch, shared.ID("known-"+id), true)); err != nil {
		t.Fatalf("persist known loss: %v", err)
	}
	knownResult, err := repo.IngestDelivery(tctx, knownBatch)
	if err != nil {
		t.Fatalf("ingest sequence after known loss: %v", err)
	}
	if knownResult.ACK.Through != 3 {
		t.Fatalf("known-loss ACK=%d, want 3", knownResult.ACK.Through)
	}
	var state string
	if err := pool.QueryRow(ctx, `SELECT state FROM telemetry_delivery_batches WHERE tenant_id=$1 AND batch_id=$2`, tenant.String(), knownBatch.Manifest.BatchID.String()).Scan(&state); err != nil {
		t.Fatalf("read acknowledged provenance: %v", err)
	}
	if state != string(ports.TelemetryStateAcknowledged) {
		t.Fatalf("known-loss batch state=%q, want %q", state, ports.TelemetryStateAcknowledged)
	}

	unknownBatch := postgresDeliveryBatchFor(t, tenant, agent, asset, 2, 2, 1, "unknown-outcome")
	if err := repo.IngestAgentGap(tctx, postgresAgentGapFor(unknownBatch, shared.ID("unknown-"+id), false)); err != nil {
		t.Fatalf("persist unknown-coordinate loss: %v", err)
	}
	unknownResult, err := repo.IngestDelivery(tctx, unknownBatch)
	if err != nil {
		t.Fatalf("ingest sequence after unknown-coordinate loss: %v", err)
	}
	if unknownResult.ACK.Through != 0 {
		t.Fatalf("unknown-coordinate loss advanced ACK to %d, want 0", unknownResult.ACK.Through)
	}
	if len(unknownResult.Gaps) != 1 || unknownResult.Gaps[0].FromSequence != 1 || unknownResult.Gaps[0].ToSequence != 2 {
		t.Fatalf("unknown-coordinate loss hid delivery gap: %+v", unknownResult.Gaps)
	}
}
