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
	shipErr       error
	seen          []fleetagent.SignedTelemetryBatch
	ack           *fleetclient.FleetTelemetryACK
	registerErrs  []error
	registerCalls int
	registeredIDs []string
}

func (f *fakeTelemetryTransport) RegisterTelemetrySigningKey(_ context.Context, _ string, key fleetagent.AgentSigningKey, _ string) error {
	f.registerCalls++
	f.registeredIDs = append(f.registeredIDs, key.KeyID)
	if len(f.registerErrs) == 0 {
		return nil
	}
	err := f.registerErrs[0]
	f.registerErrs = f.registerErrs[1:]
	return err
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

func TestEnsureTelemetrySignerRegisteredRetriesSamePersistedKeyAfter429(t *testing.T) {
	dir := t.TempDir()
	r := &runner{store: fleetclient.NewCredentialStore(dir)}
	api := &fakeTelemetryTransport{registerErrs: []error{&fleetclient.HTTPStatusError{StatusCode: 429, RetryAfter: 3 * time.Second}, nil}}
	cred := fleetclient.Credential{AgentID: "agent-register", AssetID: "asset-server", Token: "secret"}

	_, err := r.ensureTelemetrySignerRegistered(context.Background(), api, cred, fleetclient.TelemetrySigner{})
	if err == nil {
		t.Fatal("first registration should surface 429")
	}
	retry, wait := telemetryRegistrationRetry(err)
	if !retry || wait != 3*time.Second {
		t.Fatalf("registration retry policy lost: retry=%t wait=%s err=%v", retry, wait, err)
	}
	registered, err := r.ensureTelemetrySignerRegistered(context.Background(), api, cred, fleetclient.TelemetrySigner{})
	if err != nil {
		t.Fatalf("second registration: %v", err)
	}
	if api.registerCalls != 2 || len(api.registeredIDs) != 2 || api.registeredIDs[0] != api.registeredIDs[1] || registered.Key.KeyID != api.registeredIDs[1] {
		t.Fatalf("retry must reuse persisted key: calls=%d ids=%v registered=%s", api.registerCalls, api.registeredIDs, registered.Key.KeyID)
	}
}

func TestTelemetryRegistrationRetryRejectsTerminal4xx(t *testing.T) {
	retry, wait := telemetryRegistrationRetry(&fleetclient.HTTPStatusError{StatusCode: 422})
	if retry || wait != 0 {
		t.Fatalf("terminal registration rejection must not spin: retry=%t wait=%s", retry, wait)
	}
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

func TestShipTelemetryPriorityNonRetryableFailureKeepsWAL(t *testing.T) {
	agentID := shared.ID("agent-reject")
	s := openShipperTestSpool(t, agentID)
	enqueueShipperRecord(t, s, 1, time.Now().UTC())
	api := &fakeTelemetryTransport{shipErr: &fleetclient.HTTPStatusError{StatusCode: 422}}
	cred := fleetclient.Credential{AgentID: agentID.String(), AssetID: "asset-server", Token: "secret"}
	shipped, retryAfter, err := (&runner{}).shipTelemetryPriority(context.Background(), s, api, cred, testTelemetrySigner(t, cred.AgentID), fleetagent.PriorityP3)
	if err == nil || shipped || retryAfter != 0 {
		t.Fatalf("expected terminal 422 rejection, shipped=%t retry=%s err=%v", shipped, retryAfter, err)
	}
	var status *fleetclient.HTTPStatusError
	if !errors.As(err, &status) || status.Retryable() {
		t.Fatalf("non-retryable contract lost: %v", err)
	}
	left, _ := s.PeekPriority(context.Background(), fleetagent.PriorityP3, ports.PeekSpoolRequest{})
	if len(left) != 1 {
		t.Fatalf("terminal HTTP rejection must not delete WAL record, left=%d", len(left))
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

func TestShipTelemetryPriorityRejectsStaleNoProgressACK(t *testing.T) {
	agentID := shared.ID("agent-stale-ack")
	s := openShipperTestSpool(t, agentID)
	at := time.Now().UTC()
	first := enqueueShipperRecord(t, s, 1, at)
	second := enqueueShipperRecord(t, s, 1, at.Add(time.Millisecond))
	if _, err := s.Ack(context.Background(), ports.SpoolACK{Priority: fleetagent.PriorityP3, Epoch: first.Epoch, Through: first.Sequence}); err != nil {
		t.Fatalf("prime local ACK: %v", err)
	}
	api := &fakeTelemetryTransport{ack: &fleetclient.FleetTelemetryACK{Priority: fleetagent.PriorityP3, Epoch: second.Epoch, Through: first.Sequence}}
	cred := fleetclient.Credential{AgentID: agentID.String(), AssetID: "asset-server", Token: "secret"}
	shipped, _, err := (&runner{}).shipTelemetryPriority(context.Background(), s, api, cred, testTelemetrySigner(t, cred.AgentID), fleetagent.PriorityP3)
	if err == nil || shipped {
		t.Fatalf("stale no-progress ACK must fail closed, shipped=%t err=%v", shipped, err)
	}
	left, peekErr := s.PeekPriority(context.Background(), fleetagent.PriorityP3, ports.PeekSpoolRequest{})
	if peekErr != nil {
		t.Fatal(peekErr)
	}
	if len(left) != 1 || left[0].Position.Sequence != second.Sequence {
		t.Fatalf("stale ACK must retain unacked WAL tail: %+v", left)
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
