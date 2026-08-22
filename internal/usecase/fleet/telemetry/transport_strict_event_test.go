package telemetry

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestTransportRejectsSignedUnknownEventField(t *testing.T) {
	f := newTransportFixture(t)
	batch := f.batch(t, 2, 1, 1)

	var events []json.RawMessage
	if err := json.Unmarshal(batch.Payload, &events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || len(events[0]) < 2 || events[0][len(events[0])-1] != '}' {
		t.Fatalf("unexpected fixture payload: %s", batch.Payload)
	}
	raw := append([]byte(nil), events[0][:len(events[0])-1]...)
	raw = append(raw, []byte(`,"unknown_transport_field":true}`)[1:]...)
	payload := append([]byte{'['}, raw...)
	payload = append(payload, ']')

	batch.Manifest.EventDigests[0] = fleetagent.SHA256Hex(raw)
	resigned, err := fleetagent.SignTelemetryBatch(batch.Manifest, payload, f.key.KeyID, f.private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.IngestSigned(f.ctx, f.agent, resigned); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("signed event with unknown schema field must fail closed, got %v", err)
	}
	if !f.audit.has("telemetry.batch_rejected") {
		t.Fatal("unknown signed event field rejection must be audited")
	}
}
