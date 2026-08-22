package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestPostgresTelemetryAgentGapIdempotentGrowthAndRLS(t *testing.T) {
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
	tenantA := shared.ID("tag-a-" + id)
	tenantB := shared.ID("tag-b-" + id)
	agent := shared.ID("tag-agent-" + id)
	asset := shared.ID("tag-asset-" + id)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, tenantA.String(), tenantB.String()); err != nil {
		t.Fatalf("seed tenants: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fleet_assets(id,tenant_id,kind,"key",name) VALUES($1,$2,'host',$1,$1)`, asset.String(), tenantA.String()); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fleet_agents(id,tenant_id,name,token_hash,state) VALUES($1,$2,$1,$3,'active')`, agent.String(), tenantA.String(), "gap-token-"+id); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	defer func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_agent_gaps WHERE tenant_id=$1`, tenantA.String())
		_, _ = pool.Exec(bg, `DELETE FROM fleet_agents WHERE tenant_id=$1`, tenantA.String())
		_, _ = pool.Exec(bg, `DELETE FROM fleet_assets WHERE tenant_id=$1`, tenantA.String())
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id IN ($1,$2)`, tenantA.String(), tenantB.String())
	}()

	session := fleetagent.CanonicalSessionID(agent)
	stream, err := fleetagent.TelemetryDeliveryStreamID(agent, session, fleetagent.PriorityP3)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 22, 8, 0, 0, 0, time.UTC)
	gap := ports.TelemetryAgentGap{
		TenantID: tenantA, HostID: agent, AssetID: asset, AgentID: agent, AgentSessionID: session,
		StreamID: stream, Priority: fleetagent.PriorityP3, Epoch: 1, GapID: shared.ID("gap-" + id),
		KnownSequence: false, Reason: string(ports.SpoolGapQuotaEviction), Count: 1,
		OccurredAt: now.Add(-time.Second), ReceivedAt: now,
	}
	repo := NewTelemetryAgentGapRepository(pool)
	tctxA := shared.WithTenant(ctx, tenantA)
	if err := repo.IngestAgentGap(tctxA, gap); err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	if err := repo.IngestAgentGap(tctxA, gap); err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	grown := gap
	grown.Count = 3
	grown.ReceivedAt = now.Add(time.Minute)
	if err := repo.IngestAgentGap(tctxA, grown); err != nil {
		t.Fatalf("monotonic growth: %v", err)
	}
	stored, err := repo.QueryAgentGaps(tctxA, ports.HuntQuery{AssetID: asset, Since: now.Add(-time.Hour), Until: now.Add(time.Hour)})
	if err != nil || len(stored) != 1 || stored[0].GapID != gap.GapID || stored[0].Count != 3 {
		t.Fatalf("stored gaps=%+v err=%v", stored, err)
	}
	shrunk := gap
	shrunk.ReceivedAt = now.Add(2 * time.Minute)
	if err := repo.IngestAgentGap(tctxA, shrunk); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("shrinking evidence error=%v, want conflict", err)
	}

	role := "tag_runtime_" + id
	for _, statement := range []string{
		`CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT ON telemetry_agent_gaps TO ` + role,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatalf("prepare RLS role: %v", err)
		}
	}
	defer func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DROP OWNED BY `+role)
		_, _ = pool.Exec(bg, `DROP ROLE IF EXISTS `+role)
	}()
	countAs := func(tenant shared.ID) int {
		t.Helper()
		var n int
		tenantCtx := shared.WithTenant(context.Background(), tenant)
		if err := WithTenant(tenantCtx, pool, tenant.String(), func(tx pgx.Tx) error {
			if _, err := tx.Exec(tenantCtx, `SET LOCAL ROLE `+role); err != nil {
				return err
			}
			return tx.QueryRow(tenantCtx, `SELECT count(*) FROM telemetry_agent_gaps`).Scan(&n)
		}); err != nil {
			t.Fatalf("count agent gaps as %s: %v", tenant, err)
		}
		return n
	}
	if got := countAs(tenantB); got != 0 {
		t.Fatalf("tenant B sees %d tenant A agent gaps; RLS isolation failed", got)
	}
	if got := countAs(tenantA); got != 1 {
		t.Fatalf("tenant A sees %d agent gaps, want 1", got)
	}
}
