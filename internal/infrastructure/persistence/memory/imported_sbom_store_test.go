package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importedsbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestImportedSBOMStoreSaveActiveReplacesAndCopies(t *testing.T) {
	store := NewImportedSBOMStore()
	ctx := context.Background()
	now := time.Unix(100, 0).UTC()

	first := importedsbom.Record{
		ID:              "sbom-1",
		TenantID:        "tenant-1",
		EngagementID:    "eng-1",
		Filename:        "SBOM.json",
		Format:          "cyclonedx",
		SpecVersion:     "1.4",
		TargetRef:       "product-service",
		ComponentCount:  2,
		DependencyCount: 1,
		SHA256:          "abc123",
		RawJSON:         []byte(`{"bomFormat":"CycloneDX"}`),
		CreatedBy:       "operator",
		CreatedAt:       now,
	}
	if err := store.SaveActive(ctx, first); err != nil {
		t.Fatalf("SaveActive first: %v", err)
	}
	first.RawJSON[0] = 'X'

	got, err := store.LatestByEngagement(ctx, "tenant-1", "eng-1")
	if err != nil {
		t.Fatalf("LatestByEngagement first: %v", err)
	}
	if string(got.RawJSON) != `{"bomFormat":"CycloneDX"}` {
		t.Fatalf("RawJSON was not copied on save, got %q", string(got.RawJSON))
	}
	got.RawJSON[0] = 'Y'

	again, err := store.LatestByEngagement(ctx, "tenant-1", "eng-1")
	if err != nil {
		t.Fatalf("LatestByEngagement again: %v", err)
	}
	if string(again.RawJSON) != `{"bomFormat":"CycloneDX"}` {
		t.Fatalf("RawJSON was not copied on read, got %q", string(again.RawJSON))
	}

	second := first
	second.ID = "sbom-2"
	second.SHA256 = "def456"
	second.RawJSON = []byte(`{"bomFormat":"CycloneDX","version":1}`)
	if err := store.SaveActive(ctx, second); err != nil {
		t.Fatalf("SaveActive second: %v", err)
	}
	replaced, err := store.LatestByEngagement(ctx, "tenant-1", "eng-1")
	if err != nil {
		t.Fatalf("LatestByEngagement replaced: %v", err)
	}
	if replaced.ID != "sbom-2" || replaced.SHA256 != "def456" {
		t.Fatalf("active record = %s/%s, want sbom-2/def456", replaced.ID, replaced.SHA256)
	}

	if _, err := store.LatestByEngagement(ctx, "tenant-2", "eng-1"); err == nil {
		t.Fatal("LatestByEngagement for another tenant returned nil error")
	} else if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("LatestByEngagement other tenant err = %v, want not found", err)
	}
}
