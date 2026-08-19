package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func desiredStoreState(tenant, assetID string, caps []string, now time.Time) *fleetdesired.State {
	return &fleetdesired.State{
		TenantID: shared.ID(tenant), AssetID: shared.ID(assetID), AssetKind: asset.KindHost,
		Capabilities: caps, UpdatedBy: "operator", Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
}

func TestFleetDesiredStoreTenantIsolationCopiesOrderingAndDelete(t *testing.T) {
	ctx := context.Background()
	store := NewFleetDesiredStore()
	now := time.Date(2026, 8, 19, 1, 2, 3, 0, time.UTC)
	for _, state := range []*fleetdesired.State{
		desiredStoreState("tenant-a", "asset-b", []string{"b"}, now),
		desiredStoreState("tenant-a", "asset-a", []string{"a"}, now),
		desiredStoreState("tenant-b", "asset-x", []string{"x"}, now),
	} {
		if err := store.Put(ctx, state); err != nil {
			t.Fatal(err)
		}
	}

	rows, err := store.List(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].AssetID != "asset-a" || rows[1].AssetID != "asset-b" {
		t.Fatalf("unexpected deterministic tenant list: %#v", rows)
	}
	rows[0].Capabilities[0] = "mutated"
	got, err := store.Get(ctx, "tenant-a", "asset-a")
	if err != nil {
		t.Fatal(err)
	}
	if got.Capabilities[0] != "a" {
		t.Fatalf("caller mutated stored slice: %v", got.Capabilities)
	}
	if _, err := store.Get(ctx, "tenant-a", "asset-x"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant lookup = %v, want ErrNotFound", err)
	}
	if err := store.Delete(ctx, "tenant-a", "asset-a"); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, "tenant-a", "asset-a"); err != nil {
		t.Fatalf("idempotent delete failed: %v", err)
	}
	if _, err := store.Get(ctx, "tenant-a", "asset-a"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("deleted policy lookup=%v, want ErrNotFound", err)
	}
}

func TestFleetDesiredStoreUsesStructuredKeyNotDelimiterComposition(t *testing.T) {
	ctx := context.Background()
	store := NewFleetDesiredStore()
	now := time.Date(2026, 8, 19, 1, 2, 3, 0, time.UTC)
	first := desiredStoreState("a\x00b", "c", []string{"first"}, now)
	second := desiredStoreState("a", "b\x00c", []string{"second"}, now)
	if err := store.Put(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, second); err != nil {
		t.Fatal(err)
	}
	gotFirst, err := store.Get(ctx, first.TenantID, first.AssetID)
	if err != nil {
		t.Fatal(err)
	}
	gotSecond, err := store.Get(ctx, second.TenantID, second.AssetID)
	if err != nil {
		t.Fatal(err)
	}
	if gotFirst.Capabilities[0] != "first" || gotSecond.Capabilities[0] != "second" {
		t.Fatalf("structured keys collided: first=%+v second=%+v", gotFirst, gotSecond)
	}
}

func TestFleetDesiredStorePreservedCreatedAtCannotBreakTimeOrder(t *testing.T) {
	ctx := context.Background()
	store := NewFleetDesiredStore()
	created := time.Date(2026, 8, 19, 2, 0, 0, 0, time.UTC)
	initial := desiredStoreState("tenant", "asset", []string{"process"}, created)
	if err := store.Put(ctx, initial); err != nil {
		t.Fatal(err)
	}
	older := created.Add(-time.Minute)
	update := desiredStoreState("tenant", "asset", []string{"network"}, older)
	if err := store.Put(ctx, update); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("Put error=%v, want validation error", err)
	}
	got, err := store.Get(ctx, "tenant", "asset")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Capabilities) != 1 || got.Capabilities[0] != "process" {
		t.Fatalf("invalid update changed stored state: %+v", got)
	}
}
