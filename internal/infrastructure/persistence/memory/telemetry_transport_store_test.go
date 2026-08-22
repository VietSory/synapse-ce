package memory

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func memoryAgentGapFor(batch ports.TelemetryDeliveryBatch, id shared.ID, known bool) ports.TelemetryAgentGap {
	gap := ports.TelemetryAgentGap{
		TenantID: batch.TenantID, HostID: batch.HostID, AssetID: batch.AssetID, AgentID: batch.AgentID,
		AgentSessionID: batch.AgentSessionID, StreamID: batch.Manifest.StreamID,
		Priority: batch.Manifest.Priority, Epoch: batch.Manifest.Epoch, GapID: id,
		KnownSequence: known, Reason: string(ports.SpoolGapQuotaEviction), Count: 2,
		OccurredAt: batch.Manifest.EventTimeMin.Add(-2 * time.Second), ReceivedAt: batch.ReceivedAt.Add(-time.Second),
	}
	if known {
		gap.FromSequence = 1
		gap.ToSequence = 2
	}
	return gap
}

func TestMemoryTelemetryTransportACKAdvancesAcrossDurableKnownLoss(t *testing.T) {
	store := NewTelemetryTransportStore(time.Hour, 24*time.Hour)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	ahead := memoryDeliveryBatchFor(t, 1, 2, 1, "after-known-loss")
	if err := store.IngestAgentGap(ctx, memoryAgentGapFor(ahead, "gap-known", true)); err != nil {
		t.Fatalf("ingest known loss: %v", err)
	}
	got, err := store.IngestDelivery(ctx, ahead)
	if err != nil {
		t.Fatalf("ingest sequence after known loss: %v", err)
	}
	if got.ACK.Through != 3 {
		t.Fatalf("ACK through=%d, want 3 after durable known loss 1..2", got.ACK.Through)
	}
	lane := store.delivery["tenant-a"][ahead.Manifest.StreamID.String()]
	if lane == nil || lane.batches[ahead.Manifest.BatchID].state != ports.TelemetryStateAcknowledged {
		t.Fatalf("batch provenance was not acknowledged after durable known loss: %#v", lane)
	}
}

func TestMemoryTelemetryTransportACKDoesNotAdvanceAcrossUnknownLoss(t *testing.T) {
	store := NewTelemetryTransportStore(time.Hour, 24*time.Hour)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	ahead := memoryDeliveryBatchFor(t, 1, 2, 1, "after-unknown-loss")
	if err := store.IngestAgentGap(ctx, memoryAgentGapFor(ahead, "gap-unknown", false)); err != nil {
		t.Fatalf("ingest unknown-coordinate loss: %v", err)
	}
	got, err := store.IngestDelivery(ctx, ahead)
	if err != nil {
		t.Fatalf("ingest sequence after unknown loss: %v", err)
	}
	if got.ACK.Through != 0 {
		t.Fatalf("unknown-coordinate loss advanced ACK to %d, want 0", got.ACK.Through)
	}
	if len(got.Gaps) != 1 || got.Gaps[0].FromSequence != 1 || got.Gaps[0].ToSequence != 2 {
		t.Fatalf("unknown loss hid unresolved delivery gap: %+v", got.Gaps)
	}
}
