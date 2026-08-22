package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestPostgresTelemetryDeliveryACKSurvivesRepositoryAndPoolRestart(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	id := randHex(t)
	tenant := shared.ID("td-restart-" + id)
	agent := shared.ID("agent-restart-" + id)
	asset := shared.ID("asset-restart-" + id)

	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant.String()); err != nil {
		pool.Close()
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fleet_assets(id,tenant_id,kind,"key",name) VALUES($1,$2,'host',$1,$1)`, asset.String(), tenant.String()); err != nil {
		pool.Close()
		t.Fatalf("seed canonical asset: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fleet_agents(id,tenant_id,name,token_hash,state) VALUES($1,$2,$1,$3,'active')`, agent.String(), tenant.String(), "test-token-restart-"+id); err != nil {
		pool.Close()
		t.Fatalf("seed fleet agent: %v", err)
	}

	tenantCtx := shared.WithTenant(ctx, tenant)
	first := postgresDeliveryBatchFor(t, tenant, agent, asset, 1, 0, 1, "restart-one")
	repo := NewTelemetryRepository(pool, time.Hour, 24*time.Hour)
	got, err := repo.IngestDelivery(tenantCtx, first)
	if err != nil {
		pool.Close()
		t.Fatalf("initial delivery: %v", err)
	}
	if got.ACK.Epoch != 1 || got.ACK.Through != 1 || got.NewEvents != 1 {
		pool.Close()
		t.Fatalf("initial result = %+v", got)
	}

	// Model an API process restart, not merely construction of another repository over the same
	// connection pool. The new repository must reconstruct its ACK from durable sequence rows.
	pool.Close()
	pool, err = Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("reconnect after simulated server restart: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_events WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_gaps WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_delivery_batches WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_delivery_sequences WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_delivery_streams WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM fleet_agents WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM fleet_assets WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id=$1`, tenant.String())
		pool.Close()
	})

	repo = NewTelemetryRepository(pool, time.Hour, 24*time.Hour)
	second := postgresDeliveryBatchFor(t, tenant, agent, asset, 1, 1, 1, "restart-two")
	got, err = repo.IngestDelivery(tenantCtx, second)
	if err != nil {
		t.Fatalf("delivery after restart: %v", err)
	}
	if got.ACK.Epoch != 1 || got.ACK.Through != 2 || got.NewEvents != 1 || len(got.Gaps) != 0 {
		t.Fatalf("post-restart result = %+v; durable ACK did not resume at sequence 2", got)
	}

	// Replaying the pre-restart batch must stay idempotent and must not regress the durable ACK.
	replay, err := repo.IngestDelivery(tenantCtx, first)
	if err != nil {
		t.Fatalf("pre-restart replay: %v", err)
	}
	if replay.ACK.Epoch != 1 || replay.ACK.Through != 2 || replay.NewEvents != 0 || len(replay.Gaps) != 0 {
		t.Fatalf("pre-restart replay result = %+v; ACK regressed or replay duplicated events", replay)
	}
}
