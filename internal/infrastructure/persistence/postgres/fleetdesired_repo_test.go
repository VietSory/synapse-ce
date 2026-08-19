package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
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
				_, err := tx.Exec(bg, `DELETE FROM fleet_agents WHERE tenant_id=$1`, tenant)
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

	agents := NewFleetAgentRepository(pool)
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		tenant string
		agent  string
	}{
		{tenant: "fd-a", agent: "agent-a"},
		{tenant: "fd-b", agent: "agent-b"},
	} {
		agent, err := fleetagent.NewAgent(shared.ID(tc.agent), shared.ID(tc.tenant), tc.agent, "linux", "", "1.0.0", []string{"telemetry.process"}, "test-token-hash", now)
		if err != nil {
			t.Fatalf("new agent %s: %v", tc.agent, err)
		}
		if err := agents.CreateAgent(ctx, agent); err != nil {
			t.Fatalf("create agent %s: %v", tc.agent, err)
		}
	}

	repo := NewFleetDesiredRepository(pool)
	state := &fleetdesired.State{
		TenantID:     shared.ID("fd-a"),
		AgentID:      shared.ID("agent-a"),
		Capabilities: []string{"inventory.host", "telemetry.process"},
		UpdatedBy:    shared.ID("operator-a"),
		Audit:        shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
	if err := repo.Put(ctx, state); err != nil {
		t.Fatalf("put desired state: %v", err)
	}

	got, err := repo.Get(ctx, shared.ID("fd-a"), shared.ID("agent-a"))
	if err != nil {
		t.Fatalf("get desired state: %v", err)
	}
	if len(got.Capabilities) != 2 || got.Capabilities[0] != "inventory.host" || got.Capabilities[1] != "telemetry.process" {
		t.Fatalf("desired capabilities did not round-trip: %+v", got.Capabilities)
	}
	if got.UpdatedBy != shared.ID("operator-a") || !got.Audit.CreatedAt.Equal(now) {
		t.Fatalf("desired attribution/audit did not round-trip: %+v", got)
	}

	// Tenant scoping is both in the query and in WithTenant/RLS: another tenant must observe the same
	// canonical AgentID as absent rather than learning that a desired policy exists elsewhere.
	if _, err := repo.Get(ctx, shared.ID("fd-b"), shared.ID("agent-a")); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant desired lookup = %v, want ErrNotFound", err)
	}
	rows, err := repo.List(ctx, shared.ID("fd-a"))
	if err != nil || len(rows) != 1 || rows[0].AgentID != shared.ID("agent-a") {
		t.Fatalf("tenant desired list mismatch: rows=%+v err=%v", rows, err)
	}

	// Critical #633 invariant: desired state is operator intent, not an owned child of the observed
	// agent row. Purging an observed identity must retain the expectation so reconciliation can surface
	// agent_missing instead of silently going green/empty. The delete must run under tenant RLS and we
	// assert the row count; otherwise a denied zero-row DELETE would make this test vacuously pass.
	var deleted int64
	if err := WithTenant(ctx, pool, "fd-a", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM fleet_agents WHERE tenant_id=$1 AND id=$2`, "fd-a", "agent-a")
		if err == nil {
			deleted = tag.RowsAffected()
		}
		return err
	}); err != nil {
		t.Fatalf("purge observed agent: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("purge observed agent deleted %d rows, want 1", deleted)
	}
	if _, err := agents.GetAgent(ctx, "fd-a", "agent-a"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("observed agent still exists after purge: %v", err)
	}
	if _, err := repo.Get(ctx, shared.ID("fd-a"), shared.ID("agent-a")); err != nil {
		t.Fatalf("desired intent must survive observed-agent purge: %v", err)
	}
}
