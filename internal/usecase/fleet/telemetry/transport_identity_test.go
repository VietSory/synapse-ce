package telemetry

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestTransportRejectsAuthenticatedHostMismatch(t *testing.T) {
	f := newTransportFixture(t)
	batch := f.batch(t, 2, 1, 1)
	batch.Manifest.HostID = shared.ID("host-forged")
	resigned, err := fleetagent.SignTelemetryBatch(batch.Manifest, batch.Payload, f.key.KeyID, f.private)
	if err != nil {
		t.Fatalf("re-sign forged host fixture: %v", err)
	}
	if _, err := f.svc.IngestSigned(f.ctx, f.agent, resigned); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("host mismatch must be forbidden, got %v", err)
	}
	if !f.audit.has("telemetry.batch_rejected") {
		t.Fatal("host identity rejection must be audited")
	}
}

func TestTransportRejectsAuthenticatedSessionMismatch(t *testing.T) {
	f := newTransportFixture(t)
	batch := f.batch(t, 2, 1, 1)
	forgedSession := fleetagent.SessionID("session-forged")
	streamID, err := fleetagent.TelemetryDeliveryStreamID(f.agent.ID, forgedSession, batch.Manifest.Priority)
	if err != nil {
		t.Fatalf("derive forged delivery stream: %v", err)
	}
	batch.Manifest.AgentSessionID = forgedSession
	batch.Manifest.StreamID = streamID
	resigned, err := fleetagent.SignTelemetryBatch(batch.Manifest, batch.Payload, f.key.KeyID, f.private)
	if err != nil {
		t.Fatalf("re-sign forged session fixture: %v", err)
	}
	if _, err := f.svc.IngestSigned(f.ctx, f.agent, resigned); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("session mismatch must be forbidden, got %v", err)
	}
	if !f.audit.has("telemetry.batch_rejected") {
		t.Fatal("session identity rejection must be audited")
	}
}
