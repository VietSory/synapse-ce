package memory

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	dtelemetry "github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func memoryDeliveryBatchFor(t *testing.T, epoch, previous uint64, count int, suffix string) ports.TelemetryDeliveryBatch {
	t.Helper()
	tenant := shared.ID("tenant-a")
	agent := shared.ID("agent-a")
	asset := shared.ID("asset-a")
	session := fleetagent.CanonicalSessionID(agent)
	stream, err := fleetagent.TelemetryDeliveryStreamID(agent, session, fleetagent.PriorityP3)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 22, 0, 0, 0, 0, time.UTC)
	envelopes := make([]dtelemetry.TelemetryEnvelope, count)
	projected := make([]detection.Event, count)
	ids := make([]shared.ID, count)
	digests := make([]string, count)
	for i := 0; i < count; i++ {
		seq := previous + uint64(i) + 1
		id := shared.ID(fmt.Sprintf("event-%d-%s", seq, suffix))
		ids[i] = id
		digests[i] = fleetagent.SHA256Hex([]byte(id))
		obs := &dtelemetry.ProcessObservation{Kind: "exec", PID: int(seq) + 10, EntityID: shared.ID(fmt.Sprintf("pe-%d-%s", seq, suffix)), Comm: "sh", Path: "/bin/sh"}
		event := dtelemetry.TelemetryEvent{Class: detection.ClassProcess, Process: obs}
		envelopes[i] = dtelemetry.TelemetryEnvelope{
			SchemaVersion: 1, EventID: id, EventType: event.EventType(), EventClass: detection.ClassProcess,
			AgentID: agent, AssetID: asset, OccurredAt: at.Add(time.Duration(seq) * time.Second),
			ObservedAt: at.Add(time.Duration(seq) * time.Second), ReceivedAt: at.Add(time.Minute), Event: event,
		}
		projected[i] = detection.Event{
			Class: detection.ClassProcess, At: envelopes[i].OccurredAt, Host: agent,
			Process: &detection.ProcessEvent{PID: obs.PID, Comm: obs.Comm, Path: obs.Path},
		}
	}
	sequence := previous + uint64(count)
	payloadDigest := fleetagent.SHA256Hex([]byte(fmt.Sprintf("payload-%d-%d-%s", epoch, sequence, suffix)))
	manifest := fleetagent.TelemetryBatchManifest{
		ProtocolVersion: 1, SchemaVersion: 1,
		BatchID: fleetagent.DeriveTelemetryBatchID(agent, session, stream, epoch, sequence, payloadDigest),
		AgentID: agent, HostID: agent, AgentSessionID: session, AssetID: asset, StreamID: stream,
		Priority: fleetagent.PriorityP3, Epoch: epoch, Sequence: sequence, PreviousSequence: previous,
		EventTimeMin: envelopes[0].OccurredAt, EventTimeMax: envelopes[len(envelopes)-1].OccurredAt,
		ObservedCount: uint64(count), KeptCount: uint64(count),
		SamplingPolicyDigest: fleetagent.SHA256Hex([]byte("keep-all")), EventIDs: ids, EventDigests: digests,
		PayloadDigest: payloadDigest,
	}
	return ports.TelemetryDeliveryBatch{
		TenantID: tenant, HostID: agent, AssetID: asset, AgentID: agent, AgentSessionID: session,
		Manifest: manifest, KeyID: "key-a", Envelopes: envelopes, ProjectedEvents: projected,
		ReceivedAt: at.Add(time.Minute),
	}
}

func TestMemoryTelemetryDeliveryIdempotentAndRebootSafe(t *testing.T) {
	store := NewTelemetryStore(time.Hour, 24*time.Hour)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	first := memoryDeliveryBatchFor(t, 1, 0, 2, "first")

	got, err := store.IngestDelivery(ctx, first)
	if err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	if got.ACK.Through != 2 || got.NewEvents != 2 {
		t.Fatalf("first result = %+v, want ACK=2 new=2", got)
	}
	duplicate, err := store.IngestDelivery(ctx, first)
	if err != nil {
		t.Fatalf("duplicate ingest: %v", err)
	}
	if duplicate.ACK.Through != 2 || duplicate.NewEvents != 0 || len(store.rows["tenant-a"]) != 2 {
		t.Fatalf("duplicate result=%+v rows=%d, want no duplicate rows", duplicate, len(store.rows["tenant-a"]))
	}

	// A reboot advances Epoch and legitimately resets sequence to one. It must not
	// alias epoch one's sequence one in the event store/idempotency key.
	reboot := memoryDeliveryBatchFor(t, 2, 0, 1, "reboot")
	got, err = store.IngestDelivery(ctx, reboot)
	if err != nil {
		t.Fatalf("reboot ingest: %v", err)
	}
	if got.ACK.Epoch != 2 || got.ACK.Through != 1 || got.NewEvents != 1 || len(store.rows["tenant-a"]) != 3 {
		t.Fatalf("reboot result=%+v rows=%d", got, len(store.rows["tenant-a"]))
	}
	if store.rows["tenant-a"][0].deliveryKey == store.rows["tenant-a"][2].deliveryKey {
		t.Fatal("epoch reset reused a delivery key")
	}
}

func TestMemoryTelemetryDeliveryGapPersistsAndResolves(t *testing.T) {
	store := NewTelemetryStore(time.Hour, 24*time.Hour)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	// Sequence 3 arrives first. Manifest range itself is contiguous (3..3), but
	// durable history proves 1..2 are missing, so ACK stays zero and a gap persists.
	ahead := memoryDeliveryBatchFor(t, 1, 2, 1, "three")
	got, err := store.IngestDelivery(ctx, ahead)
	if err != nil {
		t.Fatalf("ahead ingest: %v", err)
	}
	if got.ACK.Through != 0 || len(got.Gaps) != 1 || got.Gaps[0].FromSequence != 1 || got.Gaps[0].ToSequence != 2 {
		t.Fatalf("ahead result = %+v", got)
	}
	q := ports.HuntQuery{HostID: "agent-a", Class: detection.ClassProcess, Since: ahead.Manifest.EventTimeMin.Add(-time.Minute), Until: ahead.Manifest.EventTimeMax.Add(time.Minute)}
	gaps, err := store.QueryDeliveryGaps(ctx, q)
	if err != nil || len(gaps) != 1 {
		t.Fatalf("query gaps = %+v err=%v", gaps, err)
	}
	hunt, err := store.Query(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if hunt.Complete {
		t.Fatal("hunt crossing an unresolved transport gap reported Complete=true")
	}

	fill := memoryDeliveryBatchFor(t, 1, 0, 2, "fill")
	got, err = store.IngestDelivery(ctx, fill)
	if err != nil {
		t.Fatalf("gap fill: %v", err)
	}
	if got.ACK.Through != 3 || len(got.Gaps) != 0 {
		t.Fatalf("gap-fill result = %+v, want ACK=3 and no current gaps", got)
	}
	gaps, err = store.QueryDeliveryGaps(ctx, q)
	if err != nil || len(gaps) != 0 {
		t.Fatalf("resolved gaps = %+v err=%v", gaps, err)
	}
	if len(store.deliveryGaps["tenant-a"]) == 0 || store.deliveryGaps["tenant-a"][0].ResolvedAt == nil {
		t.Fatal("resolved gap provenance was deleted instead of retained")
	}
}

func TestMemoryTelemetryDeliveryRejectsConflictingCoordinate(t *testing.T) {
	store := NewTelemetryStore(time.Hour, 24*time.Hour)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	if _, err := store.IngestDelivery(ctx, memoryDeliveryBatchFor(t, 1, 0, 1, "one")); err != nil {
		t.Fatal(err)
	}
	_, err := store.IngestDelivery(ctx, memoryDeliveryBatchFor(t, 1, 0, 1, "different"))
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("conflicting coordinate error=%v, want ErrConflict", err)
	}
}

func TestMemoryTelemetryAssetBindingTenantScoped(t *testing.T) {
	store := NewTelemetryStore(time.Hour, 24*time.Hour)
	at := time.Date(2026, 8, 22, 1, 0, 0, 0, time.UTC)
	ctxA := shared.WithTenant(context.Background(), "tenant-a")
	ctxB := shared.WithTenant(context.Background(), "tenant-b")
	if err := store.BindTelemetryAsset(ctxA, ports.TelemetryAssetBinding{TenantID: "tenant-a", AgentID: "agent-a", AssetID: "asset-a", UpdatedAt: at}); err != nil {
		t.Fatal(err)
	}
	asset, err := store.ResolveTelemetryAsset(ctxA, "agent-a")
	if err != nil || asset != "asset-a" {
		t.Fatalf("resolved asset=%q err=%v", asset, err)
	}
	if _, err := store.ResolveTelemetryAsset(ctxB, "agent-a"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant resolve error=%v, want not found", err)
	}
	if err := store.BindTelemetryAsset(ctxB, ports.TelemetryAssetBinding{TenantID: "tenant-a", AgentID: "agent-a", AssetID: "asset-b", UpdatedAt: at}); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("cross-tenant bind error=%v, want forbidden", err)
	}
}
