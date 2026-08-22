package telemetry

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	dtelemetry "github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/normalize"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type transportFixture struct {
	svc      *TransportService
	store    *memory.TelemetryStore
	keys     *memory.AgentSigningKeyStore
	audit    *fakeAudit
	agent    *fleetagent.Agent
	ctx      context.Context
	assetID  shared.ID
	private  ed25519.PrivateKey
	key      fleetagent.AgentSigningKey
	now      time.Time
}

func newTransportFixture(t *testing.T) *transportFixture {
	t.Helper()
	now := time.Unix(2_000_000, 0).UTC()
	agent, err := fleetagent.NewAgent("agent-a3", "t1", "host-a3", "linux", "", "1.0.0", nil, "token-hash", now)
	if err != nil {
		t.Fatal(err)
	}
	store := memory.NewTelemetryStore(7*24*time.Hour, 30*24*time.Hour)
	keys := memory.NewAgentSigningKeyStore()
	audit := &fakeAudit{}
	svc, err := NewTransportService(store, keys, store, audit, fixedClock{t: now}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(context.Background(), agent.TenantID)
	assetID := shared.ID("asset-canonical")
	if err := store.BindTelemetryAsset(ctx, ports.TelemetryAssetBinding{TenantID: agent.TenantID, AgentID: agent.ID, AssetID: assetID, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := fleetagent.NewSigningKey(agent.ID, fleetagent.PurposeTelemetryBatch, pub, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.Register(ctx, key); err != nil {
		t.Fatal(err)
	}
	return &transportFixture{svc: svc, store: store, keys: keys, audit: audit, agent: agent, ctx: ctx, assetID: assetID, private: priv, key: key, now: now}
}

func (f *transportFixture) batch(t *testing.T, schema int, epoch, sequence uint64) fleetagent.SignedTelemetryBatch {
	t.Helper()
	session := fleetagent.CanonicalSessionID(f.agent.ID)
	eventAt := f.now.Add(-time.Second + time.Duration(sequence)*time.Millisecond)
	env, err := (normalize.Normalizer{}).Normalize(normalize.DecodedEvent{
		Class: detection.ClassProcess, AgentID: f.agent.ID, AgentSessionID: shared.ID(session),
		AssetID: f.assetID, BootID: shared.ID("boot-" + time.Unix(int64(epoch), 0).Format("150405")),
		StreamID: shared.ID("sensor-process"), SensorID: "sensor", SensorVersion: "1",
		Sequence: sequence, OccurredAt: eventAt, ObservedAt: eventAt,
		Process: &normalize.DecodedProcess{Kind: "exec", PID: int(sequence) + 10, PPID: 1, Comm: "proc", Path: "/usr/bin/proc", UID: 1000},
	})
	if err != nil {
		t.Fatal(err)
	}
	if schema == 1 {
		env.SchemaVersion = 1
		env.OccurredAtSource = ""
		if err := env.Validate(); err != nil {
			t.Fatalf("v1 envelope: %v", err)
		}
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	payload := append([]byte{'['}, raw...)
	payload = append(payload, ']')
	streamID, err := fleetagent.TelemetryDeliveryStreamID(f.agent.ID, session, fleetagent.PriorityP3)
	if err != nil {
		t.Fatal(err)
	}
	manifest := fleetagent.TelemetryBatchManifest{
		ProtocolVersion: 1, SchemaVersion: schema,
		AgentID: f.agent.ID, HostID: f.agent.ID, AgentSessionID: session, AssetID: f.assetID,
		StreamID: streamID, Priority: fleetagent.PriorityP3, Epoch: epoch,
		Sequence: sequence, PreviousSequence: sequence - 1,
		EventTimeMin: env.ObservedAt, EventTimeMax: env.ObservedAt,
		ObservedCount: 1, KeptCount: 1,
		SamplingPolicyDigest: fleetagent.SHA256Hex([]byte("sampling:none:v1")),
		EventIDs: []shared.ID{env.EventID}, EventDigests: []string{fleetagent.SHA256Hex(raw)},
	}
	batch, err := fleetagent.SignTelemetryBatch(manifest, payload, f.key.KeyID, f.private)
	if err != nil {
		t.Fatal(err)
	}
	return batch
}

func TestTransportIdempotentRedeliveryAndACK(t *testing.T) {
	f := newTransportFixture(t)
	batch := f.batch(t, dtelemetry.SchemaVersion, 1, 1)
	first, err := f.svc.IngestSigned(f.ctx, f.agent, batch)
	if err != nil {
		t.Fatal(err)
	}
	if first.NewEvents != 1 || first.ACK.Through != 1 {
		t.Fatalf("first ingest = %+v", first)
	}
	second, err := f.svc.IngestSigned(f.ctx, f.agent, batch)
	if err != nil {
		t.Fatal(err)
	}
	if second.NewEvents != 0 || second.ACK.Through != 1 {
		t.Fatalf("redelivery must be idempotent, got %+v", second)
	}
}

func TestTransportRebootResetSequenceIsNewIncarnation(t *testing.T) {
	f := newTransportFixture(t)
	if _, err := f.svc.IngestSigned(f.ctx, f.agent, f.batch(t, 2, 1, 1)); err != nil {
		t.Fatal(err)
	}
	res, err := f.svc.IngestSigned(f.ctx, f.agent, f.batch(t, 2, 2, 1))
	if err != nil {
		t.Fatalf("higher epoch sequence reset must be accepted: %v", err)
	}
	if res.NewEvents != 1 || res.ACK.Epoch != 2 || res.ACK.Through != 1 {
		t.Fatalf("unexpected reboot result: %+v", res)
	}
}

func TestTransportPersistsQueryableForwardGap(t *testing.T) {
	f := newTransportFixture(t)
	if _, err := f.svc.IngestSigned(f.ctx, f.agent, f.batch(t, 2, 1, 1)); err != nil {
		t.Fatal(err)
	}
	res, err := f.svc.IngestSigned(f.ctx, f.agent, f.batch(t, 2, 1, 3))
	if err != nil {
		t.Fatal(err)
	}
	if res.ACK.Through != 1 || len(res.Gaps) != 1 || res.Gaps[0].FromSequence != 2 || res.Gaps[0].ToSequence != 2 {
		t.Fatalf("forward hole must stay explicit and block contiguous ACK: %+v", res)
	}
	gaps, err := f.store.QueryDeliveryGaps(f.ctx, ports.HuntQuery{AssetID: f.assetID})
	if err != nil || len(gaps) != 1 || gaps[0].FromSequence != 2 {
		t.Fatalf("gap must be durable/queryable: gaps=%+v err=%v", gaps, err)
	}
}

func TestTransportAcceptsV1AndV2AndRejectsOutOfRange(t *testing.T) {
	f := newTransportFixture(t)
	if _, err := f.svc.IngestSigned(f.ctx, f.agent, f.batch(t, 1, 1, 1)); err != nil {
		t.Fatalf("v1 must remain accepted: %v", err)
	}
	if _, err := f.svc.IngestSigned(f.ctx, f.agent, f.batch(t, 2, 1, 2)); err != nil {
		t.Fatalf("v2 must be accepted concurrently: %v", err)
	}
	bad := f.batch(t, 2, 1, 3)
	bad.Manifest.SchemaVersion = 99
	if _, err := f.svc.IngestSigned(f.ctx, f.agent, bad); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unsupported schema must fail closed, got %v", err)
	}
}

func TestTransportRejectsAuthenticatedAgentMismatch(t *testing.T) {
	f := newTransportFixture(t)
	other, err := fleetagent.NewAgent("agent-other", "t1", "other", "linux", "", "1.0.0", nil, "hash", f.now)
	if err != nil {
		t.Fatal(err)
	}
	session := fleetagent.CanonicalSessionID(other.ID)
	streamID, _ := fleetagent.TelemetryDeliveryStreamID(other.ID, session, fleetagent.PriorityP3)
	batch := f.batch(t, 2, 1, 1)
	batch.Manifest.AgentID = other.ID
	batch.Manifest.HostID = other.ID
	batch.Manifest.AgentSessionID = session
	batch.Manifest.StreamID = streamID
	batch.Manifest.BatchID = fleetagent.DeriveTelemetryBatchID(other.ID, session, streamID, batch.Manifest.Epoch, batch.Manifest.Sequence, batch.Manifest.PayloadDigest)
	if err := batch.Validate(); err != nil {
		t.Fatalf("mismatch fixture must remain structurally valid: %v", err)
	}
	if _, err := f.svc.IngestSigned(f.ctx, f.agent, batch); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("agent mismatch must be forbidden, got %v", err)
	}
	if !f.audit.has("telemetry.batch_rejected") {
		t.Fatal("identity rejection must be audited")
	}
}

func TestTransportRejectsSignedAssetMismatch(t *testing.T) {
	f := newTransportFixture(t)
	batch := f.batch(t, 2, 1, 1)
	batch.Manifest.AssetID = "asset-forged"
	resigned, err := fleetagent.SignTelemetryBatch(batch.Manifest, batch.Payload, f.key.KeyID, f.private)
	if err != nil {
		t.Fatalf("re-sign forged asset fixture: %v", err)
	}
	if _, err := f.svc.IngestSigned(f.ctx, f.agent, resigned); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("server asset binding mismatch must be forbidden, got %v", err)
	}
	if !f.audit.has("telemetry.batch_rejected") {
		t.Fatal("asset mismatch rejection must be audited")
	}
}

func TestTransportRejectsTamperedSignature(t *testing.T) {
	f := newTransportFixture(t)
	batch := f.batch(t, 2, 1, 1)
	batch.Signature[0] ^= 0xff
	if _, err := f.svc.IngestSigned(f.ctx, f.agent, batch); err == nil {
		t.Fatal("tampered telemetry signature was accepted")
	}
	if !f.audit.has("telemetry.batch_rejected") {
		t.Fatal("signature rejection must be audited")
	}
}

func TestTransportUnknownKeyFailsClosedAndAudited(t *testing.T) {
	f := newTransportFixture(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := fleetagent.NewSigningKey(f.agent.ID, fleetagent.PurposeTelemetryBatch, pub, f.now.Add(-time.Hour), f.now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	original := f.key
	originalPriv := f.private
	f.key, f.private = unknown, priv
	batch := f.batch(t, 2, 1, 1)
	f.key, f.private = original, originalPriv
	if _, err := f.svc.IngestSigned(f.ctx, f.agent, batch); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("unknown key must fail closed, got %v", err)
	}
	if !f.audit.has("telemetry.batch_rejected") {
		t.Fatal("key rejection must be audited")
	}
}
