package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestFleetDesiredStoreTenantIsolationAndCopies(t *testing.T) {
	ctx := context.Background()
	store := NewFleetDesiredStore()
	now := time.Date(2026, 8, 19, 1, 2, 3, 0, time.UTC)
	put := func(tenant, agent string, caps []string) {
		t.Helper()
		state := &fleetdesired.State{
			TenantID: shared.ID(tenant), AgentID: shared.ID(agent), Capabilities: caps, UpdatedBy: shared.ID("operator"),
			Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
		}
		if err := store.Put(ctx, state); err != nil {
			t.Fatal(err)
		}
	}
	put("tenant-a", "agent-b", []string{"b"})
	put("tenant-a", "agent-a", []string{"a"})
	put("tenant-b", "agent-x", []string{"x"})

	rows, err := store.List(ctx, shared.ID("tenant-a"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].AgentID != shared.ID("agent-a") || rows[1].AgentID != shared.ID("agent-b") {
		t.Fatalf("unexpected deterministic tenant list: %#v", rows)
	}
	rows[0].Capabilities[0] = "mutated"
	got, err := store.Get(ctx, shared.ID("tenant-a"), shared.ID("agent-a"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Capabilities[0] != "a" {
		t.Fatalf("caller mutated stored slice: %v", got.Capabilities)
	}
	if _, err := store.Get(ctx, shared.ID("tenant-a"), shared.ID("agent-x")); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant lookup = %v, want ErrNotFound", err)
	}
}

func TestFleetDesiredStorePreservedCreatedAtCannotBreakTimeOrder(t *testing.T) {
	ctx := context.Background()
	store := NewFleetDesiredStore()
	created := time.Date(2026, 8, 19, 2, 0, 0, 0, time.UTC)
	initial := &fleetdesired.State{
		TenantID: "tenant", AgentID: "agent", Capabilities: []string{"process"}, UpdatedBy: "operator",
		Audit: shared.Audit{CreatedAt: created, UpdatedAt: created},
	}
	if err := store.Put(ctx, initial); err != nil {
		t.Fatal(err)
	}
	// This document is internally valid before Put, but preserving the existing created_at would make
	// its updated_at older than created_at. Memory must reject it just as the Postgres CHECK does.
	older := created.Add(-time.Minute)
	update := &fleetdesired.State{
		TenantID: "tenant", AgentID: "agent", Capabilities: []string{"network"}, UpdatedBy: "operator",
		Audit: shared.Audit{CreatedAt: older, UpdatedAt: older},
	}
	if err := store.Put(ctx, update); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("Put error=%v, want validation error", err)
	}
	got, err := store.Get(ctx, "tenant", "agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Capabilities) != 1 || got.Capabilities[0] != "process" {
		t.Fatalf("invalid update changed stored state: %+v", got)
	}
}
