package telemetry

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func signedGapForFixture(t *testing.T, f *transportFixture, id shared.ID, count uint64) fleetagent.SignedTelemetryGap {
	t.Helper()
	session := fleetagent.CanonicalSessionID(f.agent.ID)
	stream, err := fleetagent.TelemetryDeliveryStreamID(f.agent.ID, session, fleetagent.PriorityP3)
	if err != nil {
		t.Fatal(err)
	}
	manifest := fleetagent.TelemetryGapManifest{
		ProtocolVersion: 1, GapID: id, AgentID: f.agent.ID, HostID: f.agent.ID,
		AgentSessionID: session, AssetID: f.assetID, StreamID: stream, Priority: fleetagent.PriorityP3,
		Epoch: 1, KnownSequence: false, Reason: string(ports.SpoolGapQuotaEviction), Count: count,
		OccurredAt: f.now.Add(-time.Second),
	}
	signed, err := fleetagent.SignTelemetryGap(manifest, f.key.KeyID, f.private)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestGapTransportPersistsIdempotentlyAndAdvancesCoalescedEvidence(t *testing.T) {
	f := newTransportFixture(t)
	gaps := memory.NewTelemetryAgentGapStore()
	svc, err := NewGapTransportService(f.svc, gaps)
	if err != nil {
		t.Fatal(err)
	}
	first := signedGapForFixture(t, f, "gap-coalesced", 1)
	id, err := svc.IngestGapSigned(f.ctx, f.agent, first)
	if err != nil || id != first.Manifest.GapID {
		t.Fatalf("first gap ingest id=%q err=%v", id, err)
	}
	if _, err := svc.IngestGapSigned(f.ctx, f.agent, first); err != nil {
		t.Fatalf("exact gap retry must be idempotent: %v", err)
	}
	updated := signedGapForFixture(t, f, first.Manifest.GapID, 3)
	if _, err := svc.IngestGapSigned(f.ctx, f.agent, updated); err != nil {
		t.Fatalf("monotonic coalesced gap update: %v", err)
	}
	stored, err := gaps.QueryAgentGaps(f.ctx, ports.HuntQuery{AssetID: f.assetID})
	if err != nil || len(stored) != 1 || stored[0].GapID != first.Manifest.GapID || stored[0].Count != 3 {
		t.Fatalf("stored gaps=%+v err=%v", stored, err)
	}
}

func TestGapTransportRejectsSignedServerIdentityForgery(t *testing.T) {
	f := newTransportFixture(t)
	gaps := memory.NewTelemetryAgentGapStore()
	svc, err := NewGapTransportService(f.svc, gaps)
	if err != nil {
		t.Fatal(err)
	}
	forged := signedGapForFixture(t, f, "gap-forged-asset", 1)
	forged.Manifest.AssetID = "asset-attacker"
	forged, err = fleetagent.SignTelemetryGap(forged.Manifest, f.key.KeyID, f.private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.IngestGapSigned(f.ctx, f.agent, forged); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("signed forged asset error=%v, want forbidden", err)
	}
	stored, err := gaps.QueryAgentGaps(f.ctx, ports.HuntQuery{})
	if err != nil || len(stored) != 0 {
		t.Fatalf("forged gap reached persistence: gaps=%+v err=%v", stored, err)
	}
}

func TestGapTransportRejectsTamperedSignedEvidence(t *testing.T) {
	f := newTransportFixture(t)
	gaps := memory.NewTelemetryAgentGapStore()
	svc, err := NewGapTransportService(f.svc, gaps)
	if err != nil {
		t.Fatal(err)
	}
	tampered := signedGapForFixture(t, f, "gap-tampered", 1)
	tampered.Manifest.Count = 2 // signature still commits Count=1
	if _, err := svc.IngestGapSigned(f.ctx, f.agent, tampered); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("tampered gap error=%v, want validation", err)
	}
}
