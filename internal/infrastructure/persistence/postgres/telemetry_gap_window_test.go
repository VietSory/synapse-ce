package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestPostgresTelemetryGapWindowUsesPersistedNeighborsAndLateFill(t *testing.T) {
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
	defer pool.Close()

	id := randHex(t)
	tenant := shared.ID("td-window-" + id)
	agent := shared.ID("agent-window-" + id)
	asset := shared.ID("asset-window-" + id)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fleet_assets(id,tenant_id,kind,"key",name) VALUES($1,$2,'host',$1,$1)`, asset.String(), tenant.String()); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fleet_agents(id,tenant_id,name,token_hash,state) VALUES($1,$2,$1,$3,'active')`, agent.String(), tenant.String(), "test-token-"+id); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	defer func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_events WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_gaps WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_delivery_sequences WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_delivery_batches WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_delivery_streams WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM fleet_agents WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM fleet_assets WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id=$1`, tenant.String())
	}()

	repo := NewTelemetryRepository(pool, time.Hour, 24*time.Hour)
	tctx := shared.WithTenant(ctx, tenant)
	first := postgresDeliveryBatchFor(t, tenant, agent, asset, 1, 0, 1, "one")
	ahead := postgresDeliveryBatchFor(t, tenant, agent, asset, 1, 4, 1, "five")
	if _, err := repo.IngestDelivery(tctx, first); err != nil {
		t.Fatalf("sequence 1: %v", err)
	}
	got, err := repo.IngestDelivery(tctx, ahead)
	if err != nil {
		t.Fatalf("sequence 5: %v", err)
	}
	if len(got.Gaps) != 1 || got.Gaps[0].FromSequence != 2 || got.Gaps[0].ToSequence != 4 {
		t.Fatalf("initial gap = %+v", got.Gaps)
	}
	if !got.Gaps[0].FromAt.Equal(first.Manifest.EventTimeMax) || !got.Gaps[0].ToAt.Equal(ahead.Manifest.EventTimeMin) {
		t.Fatalf("gap bounds = %s..%s, want %s..%s", got.Gaps[0].FromAt, got.Gaps[0].ToAt, first.Manifest.EventTimeMax, ahead.Manifest.EventTimeMin)
	}
	q := ports.HuntQuery{
		HostID: agent, Class: detection.ClassProcess,
		Since: first.Manifest.EventTimeMax.Add(time.Second),
		Until: ahead.Manifest.EventTimeMin.Add(-time.Second),
	}
	gaps, err := repo.QueryDeliveryGaps(tctx, q)
	if err != nil || len(gaps) != 1 {
		t.Fatalf("interior hunt must see unresolved gap: gaps=%+v err=%v", gaps, err)
	}

	middle := postgresDeliveryBatchFor(t, tenant, agent, asset, 1, 2, 1, "three")
	got, err = repo.IngestDelivery(tctx, middle)
	if err != nil {
		t.Fatalf("late fill sequence 3: %v", err)
	}
	if len(got.Gaps) != 2 || got.Gaps[0].FromSequence != 2 || got.Gaps[0].ToSequence != 2 || got.Gaps[1].FromSequence != 4 || got.Gaps[1].ToSequence != 4 {
		t.Fatalf("split gaps = %+v", got.Gaps)
	}
	if !got.Gaps[0].FromAt.Equal(first.Manifest.EventTimeMax) || !got.Gaps[0].ToAt.Equal(middle.Manifest.EventTimeMin) {
		t.Fatalf("left split gap lost neighbor window: %+v", got.Gaps[0])
	}
	if !got.Gaps[1].FromAt.Equal(middle.Manifest.EventTimeMax) || !got.Gaps[1].ToAt.Equal(ahead.Manifest.EventTimeMin) {
		t.Fatalf("right split gap lost neighbor window: %+v", got.Gaps[1])
	}
	gaps, err = repo.QueryDeliveryGaps(tctx, q)
	if err != nil || len(gaps) != 2 {
		t.Fatalf("interior hunt must remain incomplete after partial late fill: gaps=%+v err=%v", gaps, err)
	}
}
