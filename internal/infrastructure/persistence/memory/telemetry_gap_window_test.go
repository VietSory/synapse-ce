package memory

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestMemoryTelemetryGapWindowUsesPersistedNeighborsAndLateFill(t *testing.T) {
	store := NewTelemetryStore(time.Hour, 24*time.Hour)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	first := memoryDeliveryBatchFor(t, 1, 0, 1, "one")
	ahead := memoryDeliveryBatchFor(t, 1, 4, 1, "five")
	if _, err := store.IngestDelivery(ctx, first); err != nil {
		t.Fatalf("sequence 1: %v", err)
	}
	got, err := store.IngestDelivery(ctx, ahead)
	if err != nil {
		t.Fatalf("sequence 5: %v", err)
	}
	if len(got.Gaps) != 1 || got.Gaps[0].FromSequence != 2 || got.Gaps[0].ToSequence != 4 {
		t.Fatalf("initial gap = %+v", got.Gaps)
	}
	if !got.Gaps[0].FromAt.Equal(first.Manifest.EventTimeMax) || !got.Gaps[0].ToAt.Equal(ahead.Manifest.EventTimeMin) {
		t.Fatalf("gap bounds = %s..%s, want neighbor bounds %s..%s", got.Gaps[0].FromAt, got.Gaps[0].ToAt, first.Manifest.EventTimeMax, ahead.Manifest.EventTimeMin)
	}

	q := ports.HuntQuery{
		HostID: "agent-a", Class: detection.ClassProcess,
		Since: first.Manifest.EventTimeMax.Add(time.Second),
		Until: ahead.Manifest.EventTimeMin.Add(-time.Second),
	}
	gaps, err := store.QueryDeliveryGaps(ctx, q)
	if err != nil || len(gaps) != 1 {
		t.Fatalf("interior hunt must see unresolved gap: gaps=%+v err=%v", gaps, err)
	}

	middle := memoryDeliveryBatchFor(t, 1, 2, 1, "three")
	got, err = store.IngestDelivery(ctx, middle)
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
	gaps, err = store.QueryDeliveryGaps(ctx, q)
	if err != nil || len(gaps) != 2 {
		t.Fatalf("interior hunt must remain incomplete after partial late fill: gaps=%+v err=%v", gaps, err)
	}
}
