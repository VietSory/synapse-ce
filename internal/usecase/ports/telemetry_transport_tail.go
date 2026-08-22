package ports

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TelemetryAssetBinding is the server-authoritative mapping from an authenticated
// fleet agent to the canonical host asset produced by host-inventory reconciliation.
// The agent may cache AssetID for signing, but ingest always resolves this mapping
// server-side before trusting a manifest's AssetID.
type TelemetryAssetBinding struct {
	TenantID  shared.ID
	AgentID   shared.ID
	AssetID   shared.ID
	UpdatedAt time.Time
}

func (b TelemetryAssetBinding) Validate() error {
	if b.TenantID.IsZero() || b.AgentID.IsZero() || b.AssetID.IsZero() || b.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: telemetry asset binding is incomplete", shared.ErrValidation)
	}
	return nil
}

// TelemetryAssetBindingStore persists and resolves the authoritative binding.
// Implementations are tenant-scoped from context; the tenant never comes from
// the untrusted telemetry payload.
type TelemetryAssetBindingStore interface {
	BindTelemetryAsset(ctx context.Context, binding TelemetryAssetBinding) error
	ResolveTelemetryAsset(ctx context.Context, agentID shared.ID) (shared.ID, error)
}
