package telemetryingest

import (
	"context"
	"errors"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// StrictService is the production A0.1 boundary layered over the canonical #651
// ingest core. It preserves NewService for existing package-level callers/tests while
// production can require server-derived session, stream, and canonical asset identity.
type StrictService struct {
	base     *Service
	bindings ports.TelemetryAssetBindingStore
}

// NewStrictService constructs a fail-closed identity boundary around an existing
// canonical ingest service.
func NewStrictService(base *Service, bindings ports.TelemetryAssetBindingStore) (*StrictService, error) {
	if base == nil || bindings == nil {
		return nil, fmt.Errorf("%w: strict telemetry ingest needs base service and asset binding store", shared.ErrValidation)
	}
	return &StrictService{base: base, bindings: bindings}, nil
}

// NewBoundService is the production constructor: every dependency required by #624
// must be present before the endpoint is wired.
func NewBoundService(transport ports.TelemetryTransportStore, keys SigningKeyResolver, bindings ports.TelemetryAssetBindingStore, audit ports.AuditLogger, clock ports.Clock) (*StrictService, error) {
	base, err := NewService(transport, keys, audit, clock)
	if err != nil {
		return nil, err
	}
	return NewStrictService(base, bindings)
}

func (s *StrictService) Ingest(ctx context.Context, authAgentID shared.ID, req IngestRequest) (IngestResult, error) {
	m := req.Manifest
	if err := m.Validate(); err != nil {
		return IngestResult{}, err
	}
	if authAgentID.IsZero() || m.AgentID != authAgentID {
		s.base.reject(ctx, authAgentID, m, "identity_mismatch", s.base.clock.Now().UTC())
		return IngestResult{}, fmt.Errorf("%w: manifest agent %q is not the authenticated agent %q", shared.ErrForbidden, m.AgentID, authAgentID)
	}
	wantSession := fleetagent.CanonicalSessionID(authAgentID)
	if m.AgentSessionID() != wantSession {
		s.base.reject(ctx, authAgentID, m, "session_mismatch", s.base.clock.Now().UTC())
		return IngestResult{}, fmt.Errorf("%w: manifest session is not the authenticated enrollment session", shared.ErrForbidden)
	}
	wantStream, err := fleetagent.TelemetryDeliveryStreamID(authAgentID, wantSession, m.Position.Priority)
	if err != nil {
		return IngestResult{}, err
	}
	if m.StreamID != wantStream {
		s.base.reject(ctx, authAgentID, m, "stream_mismatch", s.base.clock.Now().UTC())
		return IngestResult{}, fmt.Errorf("%w: manifest stream is not server-derived for the authenticated agent/session/lane", shared.ErrForbidden)
	}
	assetID, err := s.bindings.ResolveTelemetryAsset(ctx, authAgentID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			err = fmt.Errorf("%w: telemetry asset binding is not established", shared.ErrForbidden)
		}
		s.base.reject(ctx, authAgentID, m, "asset_binding_missing", s.base.clock.Now().UTC())
		return IngestResult{}, err
	}
	if assetID.IsZero() || m.AssetID != assetID {
		s.base.reject(ctx, authAgentID, m, "asset_mismatch", s.base.clock.Now().UTC())
		return IngestResult{}, fmt.Errorf("%w: manifest asset does not match the server-authoritative host binding", shared.ErrForbidden)
	}
	return s.base.Ingest(ctx, authAgentID, req)
}
