package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestAssetStoreGetAssetByIDTenantIsolationAndCopy(t *testing.T) {
	ctx := context.Background()
	store := NewAssetStore()
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	a, err := asset.New("asset-a", "tenant-a", asset.KindHost, "machine-id/a", "host-a", map[string]string{"k": "v"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertAsset(ctx, a); err != nil {
		t.Fatal(err)
	}

	got, err := store.GetAssetByID(ctx, "tenant-a", "asset-a")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "asset-a" || got.TenantID != "tenant-a" || got.Kind != asset.KindHost {
		t.Fatalf("unexpected asset: %+v", got)
	}
	got.Attributes["k"] = "mutated"
	again, err := store.GetAssetByID(ctx, "tenant-a", "asset-a")
	if err != nil {
		t.Fatal(err)
	}
	if again.Attributes["k"] != "v" {
		t.Fatalf("caller mutated stored attributes: %+v", again.Attributes)
	}
	if _, err := store.GetAssetByID(ctx, "tenant-b", "asset-a"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant lookup=%v, want ErrNotFound", err)
	}
}
