package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	dtelemetry "github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TransportService is the live A3 agent→control-plane telemetry admission path. It is intentionally
// separate from the older TelemetryBatch compatibility ingest so the signed transport has one explicit
// trust boundary: authenticated agent identity, server asset binding, purpose-bound key verification,
// exact payload commitments, then durable delivery persistence/ACK.
type TransportService struct {
	delivery ports.TelemetryDeliveryStore
	keys     ports.AgentSigningKeyStore
	bindings ports.TelemetryAssetBindingStore
	audit    ports.AuditLogger
	clock    ports.Clock
	maxEvents int
}

// NewTransportService constructs the signed telemetry transport. maxEvents bounds one decompressed
// batch independently of the HTTP byte cap; an attacker with a valid credential cannot make admission
// allocate/validate an unbounded number of envelope objects in one request.
func NewTransportService(delivery ports.TelemetryDeliveryStore, keys ports.AgentSigningKeyStore, bindings ports.TelemetryAssetBindingStore, audit ports.AuditLogger, clock ports.Clock, maxEvents int) (*TransportService, error) {
	if delivery == nil || keys == nil || bindings == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: telemetry transport requires delivery store, key store, binding store, audit and clock", shared.ErrValidation)
	}
	if maxEvents <= 0 {
		return nil, fmt.Errorf("%w: telemetry transport max events must be positive", shared.ErrValidation)
	}
	return &TransportService{delivery: delivery, keys: keys, bindings: bindings, audit: audit, clock: clock, maxEvents: maxEvents}, nil
}

// IngestSigned verifies and durably ingests one signed batch for the already-authenticated fleet agent.
// Every security identity is compared with (or resolved from) server authority before any event is stored.
func (s *TransportService) IngestSigned(ctx context.Context, agent *fleetagent.Agent, batch fleetagent.SignedTelemetryBatch) (ports.TelemetryDeliveryResult, error) {
	if agent == nil {
		return ports.TelemetryDeliveryResult{}, fmt.Errorf("%w: telemetry transport requires an authenticated agent", shared.ErrForbidden)
	}
	ctxTenant, ok := shared.TenantFrom(ctx)
	if !ok || ctxTenant.IsZero() || ctxTenant != agent.TenantID {
		return ports.TelemetryDeliveryResult{}, fmt.Errorf("%w: telemetry transport tenant does not match authenticated agent", shared.ErrForbidden)
	}
	if err := batch.Validate(); err != nil {
		return ports.TelemetryDeliveryResult{}, s.reject(ctx, agent, batch, "invalid_batch", err)
	}
	m := batch.Manifest
	wantSession := fleetagent.CanonicalSessionID(agent.ID)
	if m.AgentID != agent.ID {
		return ports.TelemetryDeliveryResult{}, s.reject(ctx, agent, batch, "agent_mismatch", fmt.Errorf("%w: telemetry batch agent %q does not match authenticated agent", shared.ErrForbidden, m.AgentID))
	}
	// The VM agent is the canonical host principal in A0.1. A mutable display name/hostname never enters
	// this comparison. Asset identity is separate and resolved from the server-side binding below.
	if m.HostID != agent.ID {
		return ports.TelemetryDeliveryResult{}, s.reject(ctx, agent, batch, "host_mismatch", fmt.Errorf("%w: telemetry batch host %q does not match authenticated host", shared.ErrForbidden, m.HostID))
	}
	if m.AgentSessionID != wantSession {
		return ports.TelemetryDeliveryResult{}, s.reject(ctx, agent, batch, "session_mismatch", fmt.Errorf("%w: telemetry batch session does not match authenticated enrollment session", shared.ErrForbidden))
	}
	assetID, err := s.bindings.ResolveTelemetryAsset(ctx, agent.ID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			err = fmt.Errorf("%w: telemetry asset binding is not established", shared.ErrForbidden)
		}
		return ports.TelemetryDeliveryResult{}, s.reject(ctx, agent, batch, "asset_binding_missing", err)
	}
	if assetID.IsZero() || m.AssetID != assetID {
		return ports.TelemetryDeliveryResult{}, s.reject(ctx, agent, batch, "asset_mismatch", fmt.Errorf("%w: telemetry batch asset %q does not match server binding", shared.ErrForbidden, m.AssetID))
	}
	if m.KeptCount > uint64(s.maxEvents) {
		return ports.TelemetryDeliveryResult{}, fmt.Errorf("%w: telemetry batch has %d kept events, maximum is %d", shared.ErrSaturated, m.KeptCount, s.maxEvents)
	}

	key, err := s.keys.ResolveSigningKey(ctx, agent.ID, batch.KeyID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			err = fmt.Errorf("%w: telemetry signing key is unknown", shared.ErrForbidden)
		}
		return ports.TelemetryDeliveryResult{}, s.reject(ctx, agent, batch, "key_resolution_failed", err)
	}
	now := s.clock.Now().UTC()
	if err := fleetagent.VerifyTelemetryBatchWithKey(key, now, batch); err != nil {
		return ports.TelemetryDeliveryResult{}, s.reject(ctx, agent, batch, "signature_rejected", err)
	}

	rawEvents, err := decodeCommittedEvents(batch.Payload, int(m.KeptCount), s.maxEvents)
	if err != nil {
		return ports.TelemetryDeliveryResult{}, s.reject(ctx, agent, batch, "payload_decode_failed", err)
	}
	envelopes := make([]dtelemetry.TelemetryEnvelope, 0, len(rawEvents))
	projected := make([]detectionEventAlias, 0, len(rawEvents))
	for i, raw := range rawEvents {
		if got := fleetagent.SHA256Hex(raw); got != m.EventDigests[i] {
			return ports.TelemetryDeliveryResult{}, s.reject(ctx, agent, batch, "event_digest_mismatch", fmt.Errorf("%w: telemetry event %d digest mismatch", shared.ErrValidation, i))
		}
		var env dtelemetry.TelemetryEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return ports.TelemetryDeliveryResult{}, s.reject(ctx, agent, batch, "event_decode_failed", fmt.Errorf("%w: decode telemetry event %d: %v", shared.ErrValidation, i, err))
		}
		if env.EventID != m.EventIDs[i] {
			return ports.TelemetryDeliveryResult{}, s.reject(ctx, agent, batch, "event_id_mismatch", fmt.Errorf("%w: telemetry event %d id disagrees with manifest", shared.ErrValidation, i))
		}
		if env.SchemaVersion != m.SchemaVersion {
			return ports.TelemetryDeliveryResult{}, s.reject(ctx, agent, batch, "schema_mismatch", fmt.Errorf("%w: telemetry event %d schema %d disagrees with manifest %d", shared.ErrValidation, i, env.SchemaVersion, m.SchemaVersion))
		}
		if env.AgentID != agent.ID || env.AssetID != assetID {
			return ports.TelemetryDeliveryResult{}, s.reject(ctx, agent, batch, "event_identity_mismatch", fmt.Errorf("%w: telemetry event %d identity disagrees with authenticated binding", shared.ErrForbidden, i))
		}
		// v1 predates delivery identity fields and remains readable. When either optional field is present,
		// however, it must agree with the signed/server-authoritative batch. v2 producers fill both.
		if !env.AgentSessionID.IsZero() && env.AgentSessionID != shared.ID(wantSession) {
			return ports.TelemetryDeliveryResult{}, s.reject(ctx, agent, batch, "event_session_mismatch", fmt.Errorf("%w: telemetry event %d session disagrees with manifest", shared.ErrForbidden, i))
		}
		if !env.StreamID.IsZero() && env.StreamID != m.StreamID {
			return ports.TelemetryDeliveryResult{}, s.reject(ctx, agent, batch, "event_stream_mismatch", fmt.Errorf("%w: telemetry event %d stream disagrees with manifest", shared.ErrValidation, i))
		}
		if !env.ReceivedAt.IsZero() {
			return ports.TelemetryDeliveryResult{}, s.reject(ctx, agent, batch, "client_received_at", fmt.Errorf("%w: telemetry event %d attempts to set server received-at", shared.ErrForbidden, i))
		}
		if err := env.StampReceived(now); err != nil {
			return ports.TelemetryDeliveryResult{}, s.reject(ctx, agent, batch, "timestamp_rejected", err)
		}
		if err := env.Validate(); err != nil {
			return ports.TelemetryDeliveryResult{}, s.reject(ctx, agent, batch, "event_validation_failed", err)
		}
		ev, err := env.ToDetectionEvent(m.HostID)
		if err != nil {
			return ports.TelemetryDeliveryResult{}, s.reject(ctx, agent, batch, "projection_failed", err)
		}
		envelopes = append(envelopes, env)
		projected = append(projected, detectionEventAlias{event: ev})
	}

	legacy := make([]detection.Event, len(projected))
	for i := range projected {
		legacy[i] = projected[i].event
	}
	trusted := ports.TelemetryDeliveryBatch{
		TenantID: agent.TenantID, HostID: m.HostID, AssetID: assetID, AgentID: agent.ID,
		AgentSessionID: wantSession, Manifest: m, KeyID: batch.KeyID,
		Envelopes: envelopes, ProjectedEvents: legacy, ReceivedAt: now,
	}
	if err := trusted.Validate(); err != nil {
		return ports.TelemetryDeliveryResult{}, err
	}
	result, err := s.delivery.IngestDelivery(ctx, trusted)
	if err != nil {
		return ports.TelemetryDeliveryResult{}, fmt.Errorf("telemetry transport durable ingest: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor: agent.ID.String(), Action: "telemetry.batch_ingested", Target: m.BatchID.String(), At: now,
		Metadata: map[string]string{
			"tenant_id": agent.TenantID.String(), "agent_id": agent.ID.String(), "asset_id": assetID.String(),
			"schema_version": fmt.Sprint(m.SchemaVersion), "epoch": fmt.Sprint(m.Epoch),
			"through": fmt.Sprint(result.ACK.Through), "new_events": fmt.Sprint(result.NewEvents),
		},
	}); err != nil {
		// Persistence already happened; surface the custody failure loudly rather than claiming a clean
		// ingest. A retry is idempotent and can repair the audit trail without duplicating events.
		return result, fmt.Errorf("%w: telemetry batch became durable but ingest audit failed: %v", shared.ErrSaturated, err)
	}
	return result, nil
}

// detectionEventAlias keeps the import list/readability around the decode loop compact while still making
// the final trusted batch use the public detection.Event type. It has no behavior and never crosses a port.
type detectionEventAlias struct { event detection.Event }

func decodeCommittedEvents(payload []byte, want, max int) ([]json.RawMessage, error) {
	if want <= 0 || want > max {
		return nil, fmt.Errorf("%w: telemetry payload event count %d is outside the admitted range", shared.ErrValidation, want)
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("%w: telemetry payload must be a JSON event array: %v", shared.ErrValidation, err)
	}
	if len(raw) != want {
		return nil, fmt.Errorf("%w: telemetry payload has %d events, manifest commits to %d", shared.ErrValidation, len(raw), want)
	}
	return raw, nil
}

func (s *TransportService) reject(ctx context.Context, agent *fleetagent.Agent, batch fleetagent.SignedTelemetryBatch, reason string, cause error) error {
	now := s.clock.Now().UTC()
	target := batch.Manifest.BatchID.String()
	if target == "" {
		target = "uncommitted"
	}
	meta := map[string]string{"reason": reason, "agent_id": agent.ID.String(), "tenant_id": agent.TenantID.String()}
	if batch.KeyID != "" {
		meta["key_id"] = batch.KeyID
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{Actor: agent.ID.String(), Action: "telemetry.batch_rejected", Target: target, Metadata: meta, At: now}); err != nil {
		return errors.Join(cause, fmt.Errorf("telemetry rejection audit failed: %w", err))
	}
	return cause
}
