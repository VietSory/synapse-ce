package fleetagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func validTelemetryManifest(payload []byte) TelemetryBatchManifest {
	minTime := time.Date(2026, 8, 22, 1, 2, 3, 0, time.UTC)
	payloadDigest := SHA256Hex(payload)
	session := SessionID("session-1")
	stream := shared.ID("stream-1")
	agent := shared.ID("agent-1")
	return TelemetryBatchManifest{
		ProtocolVersion:      1,
		SchemaVersion:        2,
		BatchID:              DeriveTelemetryBatchID(agent, session, stream, 4, 12, payloadDigest),
		AgentID:              agent,
		AgentSessionID:       session,
		AssetID:              shared.ID("asset-1"),
		StreamID:             stream,
		Priority:             PriorityP3,
		Epoch:                4,
		Sequence:             12,
		PreviousSequence:     10,
		EventTimeMin:         minTime,
		EventTimeMax:         minTime.Add(time.Second),
		ObservedCount:        2,
		KeptCount:            2,
		SamplingPolicyDigest: SHA256Hex([]byte("keep-all")),
		EventIDs:             []shared.ID{"event-11", "event-12"},
		EventDigests:         []string{SHA256Hex([]byte("event-11")), SHA256Hex([]byte("event-12"))},
		PayloadDigest:        payloadDigest,
	}
}

func TestTelemetryBatchSignVerifyAndTamper(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`[{"event":"one"},{"event":"two"}]`)
	manifest := validTelemetryManifest(payload)
	batch, err := SignTelemetryBatch(manifest, payload, "key-1", priv)
	if err != nil {
		t.Fatalf("SignTelemetryBatch: %v", err)
	}
	if err := VerifyTelemetryBatch(batch, pub); err != nil {
		t.Fatalf("VerifyTelemetryBatch: %v", err)
	}

	t.Run("payload", func(t *testing.T) {
		tampered := batch
		tampered.Payload = append([]byte(nil), batch.Payload...)
		tampered.Payload[0] ^= 1
		if err := VerifyTelemetryBatch(tampered, pub); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("tampered payload error = %v, want validation rejection", err)
		}
	})

	t.Run("manifest", func(t *testing.T) {
		tampered := batch
		tampered.Manifest.AssetID = shared.ID("asset-other")
		if err := VerifyTelemetryBatch(tampered, pub); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("tampered manifest error = %v, want validation rejection", err)
		}
	})

	t.Run("signature", func(t *testing.T) {
		tampered := batch
		tampered.Signature = append([]byte(nil), batch.Signature...)
		tampered.Signature[0] ^= 1
		if err := VerifyTelemetryBatch(tampered, pub); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("tampered signature error = %v, want validation rejection", err)
		}
	})
}

func TestTelemetryBatchManifestRejectsSparseOrDuplicateRange(t *testing.T) {
	payload := []byte("payload")
	manifest := validTelemetryManifest(payload)

	sparse := manifest
	sparse.PreviousSequence = 9
	if err := sparse.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("sparse range error = %v, want validation rejection", err)
	}

	duplicate := manifest
	duplicate.EventIDs = []shared.ID{"event-11", "event-11"}
	if err := duplicate.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("duplicate event ids error = %v, want validation rejection", err)
	}
}

func TestTelemetryBatchIDChangesWithIncarnationOrPayload(t *testing.T) {
	agent := shared.ID("agent-1")
	session := SessionID("session-1")
	stream := shared.ID("stream-1")
	base := DeriveTelemetryBatchID(agent, session, stream, 1, 5, SHA256Hex([]byte("a")))
	if same := DeriveTelemetryBatchID(agent, session, stream, 1, 5, SHA256Hex([]byte("a"))); same != base {
		t.Fatalf("same commitment produced %q, want %q", same, base)
	}
	for name, got := range map[string]shared.ID{
		"session":  DeriveTelemetryBatchID(agent, SessionID("session-2"), stream, 1, 5, SHA256Hex([]byte("a"))),
		"epoch":    DeriveTelemetryBatchID(agent, session, stream, 2, 5, SHA256Hex([]byte("a"))),
		"sequence": DeriveTelemetryBatchID(agent, session, stream, 1, 6, SHA256Hex([]byte("a"))),
		"payload":  DeriveTelemetryBatchID(agent, session, stream, 1, 5, SHA256Hex([]byte("b"))),
	} {
		if got == base {
			t.Fatalf("%s change did not change batch id", name)
		}
	}
}
