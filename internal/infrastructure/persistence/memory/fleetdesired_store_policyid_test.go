package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestFleetDesiredStoreRejectsDuplicatePolicyIDWithinTenant(t *testing.T) {
	ctx := context.Background()
	store := NewFleetDesiredStore()
	now := time.Date(2026, 8, 19, 4, 0, 0, 0, time.UTC)
	first := desiredStoreState("tenant", "asset-a", "policy-shared", []string{"process"}, 1, now)
	second := desiredStoreState("tenant", "asset-b", "policy-shared", []string{"network"}, 1, now)
	if err := store.Put(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, second); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate PolicyID error=%v, want ErrConflict", err)
	}
	if _, err := store.Get(ctx, "tenant", "asset-b"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("conflicting policy was stored: %v", err)
	}
	got, err := store.Get(ctx, "tenant", "asset-a")
	if err != nil {
		t.Fatal(err)
	}
	if got.PolicyID != "policy-shared" || got.Capabilities[0] != "process" {
		t.Fatalf("existing policy changed after conflict: %+v", got)
	}

	// Policy IDs are tenant-scoped: the same opaque identifier in another tenant does not collide.
	otherTenant := desiredStoreState("other", "asset-x", "policy-shared", []string{"file"}, 1, now)
	if err := store.Put(ctx, otherTenant); err != nil {
		t.Fatalf("cross-tenant PolicyID reuse unexpectedly conflicted: %v", err)
	}
}
