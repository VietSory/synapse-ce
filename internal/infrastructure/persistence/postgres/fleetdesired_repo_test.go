package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestFleetDesiredRepository(t *testing.T) {
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
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	for _, tenant := range []string{"fd-a", "fd-b"} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`, tenant, tenant); err != nil {
			t.Fatalf("seed tenant %s: %v", tenant, err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, tenant := range []string{"fd-a", "fd-b"} {
			_ = WithTenant(bg, pool, tenant, func(tx pgx.Tx) error {
				if _, err := tx.Exec(bg, `DELETE FROM fleet_desired_state WHERE tenant_id=$1`, tenant); err != nil {
					return err
				}
				_, err := tx.Exec(bg, `DELETE FROM fleet_assets WHERE tenant_id=$1 AND id LIKE 'fd-asset-%'`, tenant)
				return err
			})
		}
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id IN ('fd-a','fd-b')`)
	})

	var forced bool
	if err := pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE relname='fleet_desired_state'`).Scan(&forced); err != nil {
		t.Fatalf("read desired-state RLS flag: %v", err)
	}
	if !forced {
		t.Fatal("FORCE RLS not set on fleet_desired_state")
	}

	now := time.Now().UTC().Truncate(time.Second)
	assetRepo := NewAssetRepository(pool)
	createAsset := func(tenant, id string, kind asset.Kind) {
		t.Helper()
		a, err := asset.New(shared.ID(id), shared.ID(tenant), kind, "key/"+id, id, nil, now)
		if err != nil {
			t.Fatalf("new asset %s: %v", id, err)
		}
		if err := assetRepo.UpsertAsset(ctx, a); err != nil {
			t.Fatalf("create asset %s: %v", id, err)
		}
	}
	createAsset("fd-a", "fd-asset-a", asset.KindHost)
	createAsset("fd-a", "fd-asset-c", asset.KindHost)
	createAsset("fd-b", "fd-asset-b", asset.KindCluster)

	// The narrow ID lookup must preserve the same tenant boundary as natural-key asset reads.
	gotAsset, err := assetRepo.GetAssetByID(ctx, "fd-a", "fd-asset-a")
	if err != nil || gotAsset.ID != "fd-asset-a" || gotAsset.Kind != asset.KindHost {
		t.Fatalf("asset id lookup mismatch: asset=%+v err=%v", gotAsset, err)
	}
	if _, err := assetRepo.GetAssetByID(ctx, "fd-b", "fd-asset-a"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant asset id lookup=%v, want ErrNotFound", err)
	}

	repo := NewFleetDesiredRepository(pool)
	state := &fleetdesired.State{
		TenantID:     "fd-a",
		AssetID:      "fd-asset-a",
		Capabilities: []string{"inventory.host", "telemetry.process"},
		UpdatedBy:    "operator-a",
		Audit:        shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
	if err := repo.Put(ctx, state); err != nil {
		t.Fatalf("put desired state: %v", err)
	}

	got, err := repo.Get(ctx, "fd-a", "fd-asset-a")
	if err != nil {
		t.Fatalf("get desired state: %v", err)
	}
	if len(got.Capabilities) != 2 || got.Capabilities[0] != "inventory.host" || got.Capabilities[1] != "telemetry.process" {
		t.Fatalf("desired state did not round-trip: %+v", got)
	}
	if got.UpdatedBy != "operator-a" || !got.Audit.CreatedAt.Equal(now) {
		t.Fatalf("desired attribution/audit did not round-trip: %+v", got)
	}

	updatedAt := now.Add(time.Minute)
	update := &fleetdesired.State{
		TenantID: "fd-a", AssetID: "fd-asset-a",
		Capabilities: []string{"telemetry.network"}, UpdatedBy: "operator-b",
		// The repository owns creation history and preserves the original value on conflict.
		Audit: shared.Audit{CreatedAt: now.Add(-time.Hour), UpdatedAt: updatedAt},
	}
	if err := repo.Put(ctx, update); err != nil {
		t.Fatalf("update desired state: %v", err)
	}
	got, err = repo.Get(ctx, "fd-a", "fd-asset-a")
	if err != nil {
		t.Fatalf("get updated desired state: %v", err)
	}
	if !got.Audit.CreatedAt.Equal(now) || !got.Audit.UpdatedAt.Equal(updatedAt) || got.UpdatedBy != "operator-b" || len(got.Capabilities) != 1 || got.Capabilities[0] != "telemetry.network" {
		t.Fatalf("upsert history/mutable state mismatch: %+v", got)
	}

	if _, err := repo.Get(ctx, "fd-b", "fd-asset-a"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant desired lookup=%v, want ErrNotFound", err)
	}
	rows, err := repo.List(ctx, "fd-a")
	if err != nil || len(rows) != 1 || rows[0].AssetID != "fd-asset-a" {
		t.Fatalf("tenant desired list mismatch: rows=%+v err=%v", rows, err)
	}

	// Prove the RLS policy itself, not merely repository WHERE predicates: execute a query that asks
	// explicitly for fd-a while the session tenant is fd-b. A permissive/broken policy would leak it.
	var visible int
	if err := WithTenant(ctx, pool, "fd-b", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM fleet_desired_state WHERE tenant_id='fd-a'`).Scan(&visible)
	}); err != nil {
		t.Fatalf("direct cross-tenant RLS read: %v", err)
	}
	if visible != 0 {
		t.Fatalf("RLS leaked %d fd-a desired rows to fd-b", visible)
	}
	var crossTenantUpdated int64
	if err := WithTenant(ctx, pool, "fd-b", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE fleet_desired_state SET updated_by='intruder' WHERE tenant_id='fd-a' AND asset_id='fd-asset-a'`)
		if err == nil {
			crossTenantUpdated = tag.RowsAffected()
		}
		return err
	}); err != nil {
		t.Fatalf("direct cross-tenant RLS update: %v", err)
	}
	if crossTenantUpdated != 0 {
		t.Fatalf("RLS permitted %d cross-tenant updates", crossTenantUpdated)
	}

	// The FK independently rejects a desired row whose canonical technical asset does not exist.
	missingAsset := &fleetdesired.State{
		TenantID: "fd-a", AssetID: "fd-asset-missing", Capabilities: []string{"process"},
		UpdatedBy: "operator", Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
	if err := repo.Put(ctx, missingAsset); err == nil {
		t.Fatal("desired state for a missing canonical asset unexpectedly persisted")
	}

	// Bypass the repository validator and prove the SQL CHECK rejects a non-canonical capability array.
	var invalidInserted int64
	if err := WithTenant(ctx, pool, "fd-a", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			INSERT INTO fleet_desired_state
			  (tenant_id,asset_id,capabilities,updated_by,created_at,updated_at)
			VALUES ('fd-a','fd-asset-c',ARRAY['z','a'],'operator',now(),now())`)
		if err == nil {
			invalidInserted = tag.RowsAffected()
		}
		return err
	}); err == nil {
		t.Fatal("unsorted capability array unexpectedly bypassed database canonicality CHECK")
	}
	if invalidInserted != 0 {
		t.Fatalf("invalid direct insert affected %d rows", invalidInserted)
	}

	if err := repo.Delete(ctx, "fd-a", "fd-asset-a"); err != nil {
		t.Fatalf("delete desired state: %v", err)
	}
	if err := repo.Delete(ctx, "fd-a", "fd-asset-a"); err != nil {
		t.Fatalf("idempotent delete desired state: %v", err)
	}
	if _, err := repo.Get(ctx, "fd-a", "fd-asset-a"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("deleted desired state lookup=%v, want ErrNotFound", err)
	}
}
