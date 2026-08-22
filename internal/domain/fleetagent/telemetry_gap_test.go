package fleetagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestSignedTelemetryGapCommitsLossEvidence(t *testing.T) {
	now := time.Date(2026, 8, 22, 8, 0, 0, 0, time.UTC)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewSigningKey("agent-gap", PurposeTelemetryBatch, pub, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	session := CanonicalSessionID("agent-gap")
	stream, err := TelemetryDeliveryStreamID("agent-gap", session, PriorityP3)
	if err != nil {
		t.Fatal(err)
	}
	manifest := TelemetryGapManifest{
		ProtocolVersion: 1, GapID: "gap-1", AgentID: "agent-gap", HostID: "agent-gap",
		AgentSessionID: session, AssetID: "asset-gap", StreamID: stream, Priority: PriorityP3,
		Epoch: 4, KnownSequence: false, Reason: "quota_eviction", Count: 3, OccurredAt: now.Add(-time.Second),
	}
	signed, err := SignTelemetryGap(manifest, key.KeyID, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := VerifyTelemetryGapWithKey(key, now, signed); err != nil {
		t.Fatalf("verify: %v", err)
	}
	tampered := signed
	tampered.Manifest.Count++
	if err := VerifyTelemetryGapWithKey(key, now, tampered); err == nil {
		t.Fatal("tampered gap count verified")
	}
}

func TestTelemetryGapManifestKnownRangeMustMatchCount(t *testing.T) {
	m := TelemetryGapManifest{
		ProtocolVersion: 1, GapID: shared.ID("gap-known"), AgentID: "agent", HostID: "agent",
		AgentSessionID: "session", AssetID: "asset", StreamID: "stream", Priority: PriorityP2,
		Epoch: 1, KnownSequence: true, FromSequence: 3, ToSequence: 5, Count: 2,
		Reason: "corrupt_frame", OccurredAt: time.Now().UTC(),
	}
	if err := m.Validate(); err == nil {
		t.Fatal("range/count mismatch accepted")
	}
}

func TestTelemetryGapManifestBoundsDurableIdentifiersAndCounters(t *testing.T) {
	base := TelemetryGapManifest{
		ProtocolVersion: 1, GapID: "gap", AgentID: "agent", HostID: "agent", AgentSessionID: "session",
		AssetID: "asset", StreamID: "stream", Priority: PriorityP3, Epoch: 1,
		KnownSequence: false, Reason: "quota_eviction", Count: 1, OccurredAt: time.Now().UTC(),
	}
	tooLong := base
	tooLong.GapID = shared.ID(strings.Repeat("g", maxTelemetryGapIDBytes+1))
	if err := tooLong.Validate(); err == nil {
		t.Fatal("oversized gap id accepted")
	}
	tooLarge := base
	tooLarge.Count = maxTelemetryGapInteger + 1
	if err := tooLarge.Validate(); err == nil {
		t.Fatal("counter outside durable BIGINT range accepted")
	}
}
