package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetclient"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/spool"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeTelemetryTransport struct {
	shipErr error
	seen    []fleetagent.SignedTelemetryBatch
	ack     *fleetclient.FleetTelemetryACK
}

func (f *fakeTelemetryTransport) RegisterTelemetrySigningKey(context.Context, string, fleetagent.AgentSigningKey, string) error {
	return nil
}

func (f *fakeTelemetryTransport) ShipTelemetry(_ context.Context, _ string, batch fleetagent.SignedTelemetryBatch) (fleetclient.TelemetryShipResponse, error) {
	f.seen = append(f.seen, batch)
	if f.shipErr != nil {
		return fleetclient.TelemetryShipResponse{}, f.shipErr
	}
	ack := fleetclient.FleetTelemetryACK{Priority: batch.Manifest.Priority, Epoch: batch.Manifest.Epoch, Through: batch.Manifest.Sequence}
	if f.ack != nil {
		ack = *f.ack
	}
	return fleetclient.TelemetryShipResponse{ACK: ack, NewEvents: int(batch.Manifest.KeptCount)}, nil
}

func openShipperTestSpool(t *testing.T, agentID shared.ID) *spool.Spool {
	t.Helper()
	cfg := spool.DefaultConfig()
	cfg.Dir = t.TempDir()
	cfg.Session = fleetagent.CanonicalSessionID(agentID)
	cfg.Boot = fleetagent.BootID("boot-test")
	s, err := spool.Open(cfg)
	if err != nil {
		t.Fatalf("open spool: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func enqueueShipperRecord(t *testing.T, s *spool.Spool, schema int, at time.Time) fleetagent.StreamPosition {
	t.Helper()
	pos, err := s.Enqueue(context.Background(), ports.SpoolItem{
		Kind: ports.SpoolRecordTelemetry, Priority: fleetagent.PriorityP3,
		EventID: shared.ID("evt-" + at.Format("150405.000000000")), EventClass: detection.ClassProcess,
		ContentType: "application/vnd.synapse.telemetry-envelope+json;version=1",
		Payload: []byte(`{"schema_version":1,"event_id":"placeholder"}`), ObservedAt: at,
		MustNotShed: false, SchemaVersion: schema,
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	return pos
}

func testTelemetrySigner(t *testing.T, agentID string) fleetclient.TelemetrySigner {
	t.Helper()
	store := fleetclient.NewCredentialStore(t.TempDir())
	signer, err := store.EnsureTelemetrySigner(agentID, time.Now().UTC())
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

func TestShipTelemetryPrioritySignsAndDeletesOnlyAfterACK(t *testing.T) {
	agentID := shared.ID("agent-a3")
	s := openShipperTestSpool(t, agentID)
	at := time.Now().UTC().Truncate(time.Microsecond)
	pos := enqueueShipperRecord(t, s, 1, at)
	api := &fakeTelemetryTransport{}
	cred := fleetclient.Credential{AgentID: agentID.String(), AssetID: "asset-server", Token: "secret"}
	signer := testTelemetrySigner(t, cred.AgentID)
	shipped, _, err := (&runner{}).shipTelemetryPriority(context.Background(), s, api, cred, signer, fleetagent.PriorityP3)
	if err != nil || !shipped {
		t.Fatalf("ship: shipped=%t err=%v", shipped, err)
	}
	if len(api.seen) != 1 {
		t.Fatalf("expected one batch, got %d", len(api.seen))
	}
	batch := api.seen[0]
	if batch.Manifest.AssetID != "asset-server" || batch.Manifest.AgentSessionID != fleetagent.CanonicalSessionID(agentID) {
		t.Fatalf("batch identity is not server-canonical: %+v", batch.Manifest)
	}
	if batch.Manifest.Epoch != pos.Epoch || batch.Manifest.Sequence != pos.Sequence || batch.Manifest.PreviousSequence != pos.Sequence-1 {
		t.Fatalf("batch coordinates mismatch spool: %+v vs %+v", batch.Manifest, pos)
	}
	if err := fleetagent.VerifyTelemetryBatch(batch, signer.Key.PublicKey); err != nil {
		t.Fatalf("signed batch must verify: %v", err)
	}
	left, err := s.PeekPriority(context.Background(), fleetagent.PriorityP3, ports.PeekSpoolRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("ACKed batch must be deleted, left=%d", len(left))
	}
}

func TestShipTelemetryPriorityRetryableFailureKeepsWAL(t *testing.T) {
	agentID := shared.ID("agent-retry")
	s := openShipperTestSpool(t, agentID)
	enqueueShipperRecord(t, s, 1, time.Now().UTC())
	api := &fakeTelemetryTransport{shipErr: &fleetclient.HTTPStatusError{StatusCode: 503, RetryAfter: 2 * time.Second}}
	cred := fleetclient.Credential{AgentID: agentID.String(), AssetID: "asset-server", Token: "secret"}
	shipped, retryAfter, err := (&runner{}).shipTelemetryPriority(context.Background(), s, api, cred, testTelemetrySigner(t, cred.AgentID), fleetagent.PriorityP3)
	if err == nil || shipped || retryAfter != 2*time.Second {
		t.Fatalf("expected retryable 503, shipped=%t retry=%s err=%v", shipped, retryAfter, err)
	}
	var status *fleetclient.HTTPStatusError
	if !errors.As(err, &status) || !status.Retryable() {
		t.Fatalf("retry contract lost: %v", err)
	}
	left, _ := s.PeekPriority(context.Background(), fleetagent.PriorityP3, ports.PeekSpoolRequest{})
	if len(left) != 1 {
		t.Fatalf("HTTP failure must not delete WAL record, left=%d", len(left))
	}
}

func TestShipTelemetryPriorityRejectsForgedACK(t *testing.T) {
	agentID := shared.ID("agent-ack")
	s := openShipperTestSpool(t, agentID)
	pos := enqueueShipperRecord(t, s, 1, time.Now().UTC())
	api := &fakeTelemetryTransport{ack: &fleetclient.FleetTelemetryACK{Priority: fleetagent.PriorityP3, Epoch: pos.Epoch + 1, Through: pos.Sequence}}
	cred := fleetclient.Credential{AgentID: agentID.String(), AssetID: "asset-server", Token: "secret"}
	shipped, _, err := (&runner{}).shipTelemetryPriority(context.Background(), s, api, cred, testTelemetrySigner(t, cred.AgentID), fleetagent.PriorityP3)
	if err == nil || shipped {
		t.Fatalf("forged cross-epoch ACK must fail, shipped=%t err=%v", shipped, err)
	}
	left, _ := s.PeekPriority(context.Background(), fleetagent.PriorityP3, ports.PeekSpoolRequest{})
	if len(left) != 1 {
		t.Fatalf("invalid ACK must not delete WAL record")
	}
}

func TestContiguousTelemetryPrefixStopsAtSchemaBoundary(t *testing.T) {
	agentID := shared.ID("agent-schema")
	s := openShipperTestSpool(t, agentID)
	at := time.Now().UTC()
	enqueueShipperRecord(t, s, 1, at)
	enqueueShipperRecord(t, s, 2, at.Add(time.Millisecond))
	records, err := s.PeekPriority(context.Background(), fleetagent.PriorityP3, ports.PeekSpoolRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(contiguousTelemetryPrefix(records)); got != 1 {
		t.Fatalf("mixed schema versions must form separate batches, prefix=%d", got)
	}
}
