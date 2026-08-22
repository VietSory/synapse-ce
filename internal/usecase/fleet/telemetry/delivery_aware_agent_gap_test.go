package telemetry

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestWithAgentGapsMarksIntersectingHuntIncompleteWithoutFabricatingSequence(t *testing.T) {
	base := memory.NewTelemetryStore(time.Hour, 24*time.Hour)
	agentGaps := memory.NewTelemetryAgentGapStore()
	ctx := shared.WithTenant(context.Background(), "tenant-gap-hunt")
	at := time.Date(2026, 8, 22, 8, 0, 0, 0, time.UTC)
	session := fleetagent.CanonicalSessionID("agent-gap-hunt")
	stream, err := fleetagent.TelemetryDeliveryStreamID("agent-gap-hunt", session, fleetagent.PriorityP3)
	if err != nil {
		t.Fatal(err)
	}
	gap := ports.TelemetryAgentGap{
		TenantID: "tenant-gap-hunt", HostID: "agent-gap-hunt", AssetID: "asset-gap-hunt", AgentID: "agent-gap-hunt",
		AgentSessionID: session, StreamID: stream, Priority: fleetagent.PriorityP3, Epoch: 1, GapID: "gap-hunt",
		KnownSequence: false, Reason: string(ports.SpoolGapCorruptFrame), Count: 1, OccurredAt: at, ReceivedAt: at.Add(time.Second),
	}
	if err := agentGaps.IngestAgentGap(ctx, gap); err != nil {
		t.Fatal(err)
	}

	q := ports.HuntQuery{
		HostID: "agent-gap-hunt", AssetID: "asset-gap-hunt", Class: detection.ClassProcess,
		Since: at.Add(-time.Minute), Until: at.Add(time.Minute),
	}
	plain, err := base.Query(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if !plain.Complete {
		t.Fatalf("base store unexpectedly incomplete: %+v", plain)
	}
	wrapped := WithAgentGaps(base, agentGaps)
	got, err := wrapped.Query(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if got.Complete {
		t.Fatal("hunt intersecting unknown-coordinate agent loss reported Complete=true")
	}
	if len(got.SequenceGaps) != 0 {
		t.Fatalf("unknown-coordinate loss was fabricated into sequence gaps: %+v", got.SequenceGaps)
	}

	fileQuery := q
	fileQuery.Class = detection.ClassFile // P2; must not be poisoned by a P3-only loss record.
	got, err = wrapped.Query(ctx, fileQuery)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Complete {
		t.Fatalf("non-intersecting priority hunt was marked incomplete: %+v", got)
	}
}
