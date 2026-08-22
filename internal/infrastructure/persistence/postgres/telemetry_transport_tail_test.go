package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestTelemetryTransportTailBindingAndDurableGaps(t *testing.T) {
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

	suffix := uuid.NewString()
	tenant := shared.ID("ttail-" + suffix)
	otherTenant := shared.ID("ttail-other-" + suffix)
	agent := shared.ID("agent-" + suffix)
	otherAgent := shared.ID("agent-other-" + suffix)
	asset := shared.ID("asset-" + suffix)
	stream := shared.ID("stream-" + suffix)
	now := time.Now().UTC().Truncate(time.Microsecond)

	for _, tenantID := range []shared.ID{tenant, otherTenant} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenantID.String()); err != nil {
			t.Fatalf("seed tenant %s: %v", tenantID, err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fleet_agents(id,tenant_id,name,token_hash,state) VALUES($1,$2,$3,$4,'active')`, agent.String(), tenant.String(), "telemetry-tail-agent", "hash-1"); err != nil {
		t.Fatalf("seed fleet agent: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fleet_agents(id,tenant_id,name,token_hash,state) VALUES($1,$2,$3,$4,'active')`, otherAgent.String(), otherTenant.String(), "other-agent", "hash-2"); err != nil {
		t.Fatalf("seed other fleet agent: %v", err)
	}

	t.Cleanup(func() {
		bg := context.Background()
		for _, table := range []string{"telemetry_transport_gaps", "telemetry_stream_positions", "telemetry_asset_bindings"} {
			_, _ = pool.Exec(bg, `DELETE FROM `+table+` WHERE tenant_id IN ($1,$2)`, tenant.String(), otherTenant.String())
		}
		_, _ = pool.Exec(bg, `DELETE FROM fleet_assets WHERE tenant_id IN ($1,$2)`, tenant.String(), otherTenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM fleet_agents WHERE tenant_id IN ($1,$2)`, tenant.String(), otherTenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id IN ($1,$2)`, tenant.String(), otherTenant.String())
	})

	// Host reconciliation is the authority that establishes the telemetry asset binding.
	// reporting_agent_id is server-authored by the host-inventory use case; the trigger must
	// materialize exactly that tenant-scoped agent -> asset relationship.
	if _, err := pool.Exec(ctx, `INSERT INTO fleet_assets(id,tenant_id,kind,"key",name,attributes,created_at,updated_at)
		VALUES($1,$2,'host',$3,$4,jsonb_build_object('reporting_agent_id',$5),$6,$6)`,
		asset.String(), tenant.String(), "machine/"+suffix, "host-"+suffix, agent.String(), now); err != nil {
		t.Fatalf("seed host asset and trigger telemetry binding: %v", err)
	}

	repo := NewTelemetryTransportRepository(pool)
	tenantCtx := shared.WithTenant(ctx, tenant)
	resolved, err := repo.ResolveTelemetryAsset(tenantCtx, agent)
	if err != nil || resolved != asset {
		t.Fatalf("server-authoritative asset binding = %q, %v; want %q", resolved, err, asset)
	}
	if _, err := repo.ResolveTelemetryAsset(shared.WithTenant(ctx, otherTenant), agent); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant asset binding must be invisible, got %v", err)
	}

	// The composite FK must reject a tenant/agent pair assembled from two individually
	// valid rows. This is the invariant that a plain REFERENCES fleet_agents(id) would miss.
	if _, err := pool.Exec(ctx, `INSERT INTO telemetry_asset_bindings(tenant_id,agent_id,asset_id,updated_at) VALUES($1,$2,$3,$4)`,
		tenant.String(), otherAgent.String(), asset.String(), now); err == nil {
		t.Fatal("cross-tenant agent/tenant binding unexpectedly satisfied the composite FK")
	}

	// Materialize a missing delivery window [2,3]. ListGaps must read durable rows,
	// not derive an ephemeral answer from this repository instance's memory.
	state := ports.TelemetryStreamState{
		AgentID: agent, StreamID: stream, Epoch: 1,
		Contiguous: 1, Pending: []uint64{4}, UpdatedAt: now,
	}
	if err := repo.SaveStreamState(tenantCtx, state); err != nil {
		t.Fatalf("save gapped stream state: %v", err)
	}
	gaps, err := repo.ListGaps(tenantCtx, agent, stream)
	if err != nil || len(gaps) != 1 || gaps[0].FromSequence != 2 || gaps[0].ToSequence != 3 {
		t.Fatalf("persisted gap = %+v, %v; want [2,3]", gaps, err)
	}

	// A fresh repository over the same database must observe the same gap, proving it
	// survives process restart and is queryable from persisted state.
	restarted := NewTelemetryTransportRepository(pool)
	gaps, err = restarted.ListGaps(tenantCtx, agent, stream)
	if err != nil || len(gaps) != 1 || gaps[0].FromSequence != 2 || gaps[0].ToSequence != 3 {
		t.Fatalf("gap after repository restart = %+v, %v; want [2,3]", gaps, err)
	}
	if gaps, err := restarted.ListGaps(shared.WithTenant(ctx, otherTenant), agent, stream); err != nil || len(gaps) != 0 {
		t.Fatalf("cross-tenant gap visibility = %+v, %v; want none", gaps, err)
	}

	current, err := restarted.StreamState(tenantCtx, agent, stream, 1)
	if err != nil {
		t.Fatal(err)
	}
	current.Contiguous = 4
	current.Pending = nil
	current.UpdatedAt = now.Add(time.Second)
	if err := restarted.SaveStreamState(tenantCtx, current); err != nil {
		t.Fatalf("fill telemetry gap: %v", err)
	}
	if gaps, err := restarted.ListGaps(tenantCtx, agent, stream); err != nil || len(gaps) != 0 {
		t.Fatalf("filled gap still open: %+v, %v", gaps, err)
	}

	var resolvedHistory int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM telemetry_transport_gaps
		WHERE tenant_id=$1 AND agent_id=$2 AND stream_id=$3 AND epoch=1 AND from_sequence=2 AND to_sequence=3 AND resolved_at IS NOT NULL`,
		tenant.String(), agent.String(), stream.String()).Scan(&resolvedHistory); err != nil {
		t.Fatalf("query resolved gap history: %v", err)
	}
	if resolvedHistory != 1 {
		t.Fatalf("resolved gap provenance rows = %d, want 1", resolvedHistory)
	}
}
