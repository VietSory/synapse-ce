package telemetry

import (
	"context"
	"errors"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// GapTransportService extends the live A3 transport with signed agent-origin loss
// evidence without weakening the delivery-batch trust boundary.
type GapTransportService struct {
	*TransportService
	gaps ports.TelemetryAgentGapStore
}

func NewGapTransportService(base *TransportService, gaps ports.TelemetryAgentGapStore) (*GapTransportService, error) {
	if base == nil || gaps == nil {
		return nil, fmt.Errorf("%w: telemetry gap transport requires base transport and gap store", shared.ErrValidation)
	}
	return &GapTransportService{TransportService: base, gaps: gaps}, nil
}

func (s *GapTransportService) IngestGapSigned(ctx context.Context, agent *fleetagent.Agent, signed fleetagent.SignedTelemetryGap) (shared.ID, error) {
	if agent == nil {
		return "", fmt.Errorf("%w: telemetry gap transport requires an authenticated agent", shared.ErrForbidden)
	}
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() || tenant != agent.TenantID {
		return "", fmt.Errorf("%w: telemetry gap tenant does not match authenticated agent", shared.ErrForbidden)
	}
	if err := signed.Validate(); err != nil {
		return "", s.rejectGap(ctx, agent, signed, "invalid_gap", err)
	}
	m := signed.Manifest
	wantSession := fleetagent.CanonicalSessionID(agent.ID)
	if m.AgentID != agent.ID || m.HostID != agent.ID {
		return "", s.rejectGap(ctx, agent, signed, "identity_mismatch", fmt.Errorf("%w: telemetry gap agent/host disagrees with authenticated principal", shared.ErrForbidden))
	}
	if m.AgentSessionID != wantSession {
		return "", s.rejectGap(ctx, agent, signed, "session_mismatch", fmt.Errorf("%w: telemetry gap session disagrees with authenticated enrollment", shared.ErrForbidden))
	}
	wantStream, err := fleetagent.TelemetryDeliveryStreamID(agent.ID, wantSession, m.Priority)
	if err != nil {
		return "", s.rejectGap(ctx, agent, signed, "stream_invalid", err)
	}
	if m.StreamID != wantStream {
		return "", s.rejectGap(ctx, agent, signed, "stream_mismatch", fmt.Errorf("%w: telemetry gap stream is not server-derived", shared.ErrForbidden))
	}
	assetID, err := s.bindings.ResolveTelemetryAsset(ctx, agent.ID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			err = fmt.Errorf("%w: telemetry asset binding is not established", shared.ErrForbidden)
		}
		return "", s.rejectGap(ctx, agent, signed, "asset_binding_missing", err)
	}
	if assetID.IsZero() || m.AssetID != assetID {
		return "", s.rejectGap(ctx, agent, signed, "asset_mismatch", fmt.Errorf("%w: telemetry gap asset disagrees with server binding", shared.ErrForbidden))
	}
	if !ports.SpoolGapReason(m.Reason).Valid() {
		return "", s.rejectGap(ctx, agent, signed, "reason_invalid", fmt.Errorf("%w: telemetry gap reason %q is unsupported", shared.ErrValidation, m.Reason))
	}
	key, err := s.keys.ResolveSigningKey(ctx, agent.ID, signed.KeyID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			err = fmt.Errorf("%w: telemetry signing key is unknown", shared.ErrForbidden)
		}
		return "", s.rejectGap(ctx, agent, signed, "key_resolution_failed", err)
	}
	now := s.clock.Now().UTC()
	if err := fleetagent.VerifyTelemetryGapWithKey(key, now, signed); err != nil {
		return "", s.rejectGap(ctx, agent, signed, "signature_rejected", err)
	}
	trusted := ports.TelemetryAgentGap{
		TenantID: agent.TenantID, HostID: agent.ID, AssetID: assetID, AgentID: agent.ID,
		AgentSessionID: wantSession, StreamID: wantStream, Priority: m.Priority, Epoch: m.Epoch,
		GapID: m.GapID, KnownSequence: m.KnownSequence, FromSequence: m.FromSequence, ToSequence: m.ToSequence,
		Reason: m.Reason, Count: m.Count, OccurredAt: m.OccurredAt.UTC(), ReceivedAt: now,
	}
	if err := s.gaps.IngestAgentGap(ctx, trusted); err != nil {
		return "", fmt.Errorf("telemetry agent gap durable ingest: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor: agent.ID.String(), Action: "telemetry.agent_gap_ingested", Target: m.GapID.String(), At: now,
		Metadata: map[string]string{
			"tenant_id": agent.TenantID.String(), "asset_id": assetID.String(),
			"reason": m.Reason, "count": fmt.Sprint(m.Count),
		},
	}); err != nil {
		return m.GapID, fmt.Errorf("%w: telemetry agent gap became durable but ingest audit failed: %v", shared.ErrSaturated, err)
	}
	return m.GapID, nil
}

func (s *GapTransportService) rejectGap(ctx context.Context, agent *fleetagent.Agent, signed fleetagent.SignedTelemetryGap, reason string, cause error) error {
	now := s.clock.Now().UTC()
	target := signed.Manifest.GapID.String()
	if target == "" {
		target = "uncommitted"
	}
	meta := map[string]string{"reason": reason, "agent_id": agent.ID.String(), "tenant_id": agent.TenantID.String()}
	if signed.KeyID != "" {
		meta["key_id"] = signed.KeyID
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor: agent.ID.String(), Action: "telemetry.agent_gap_rejected", Target: target, Metadata: meta, At: now,
	}); err != nil {
		return errors.Join(cause, fmt.Errorf("telemetry gap rejection audit failed: %w", err))
	}
	return cause
}
