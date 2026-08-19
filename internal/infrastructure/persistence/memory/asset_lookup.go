package memory

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// GetAssetByID returns one canonical technical asset by server-issued ID. It is intentionally a
// narrow extension used by desired-state admission; the broad AssetRepository contract remains keyed
// by natural identity for normal observation/upsert flows.
func (s *AssetStore) GetAssetByID(_ context.Context, tenantID, id shared.ID) (*asset.Asset, error) {
	if tenantID.IsZero() || id.IsZero() {
		return nil, shared.ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.assets {
		if a.TenantID != tenantID || a.ID != id {
			continue
		}
		cp := *a
		cp.Attributes = cloneMap(a.Attributes)
		return &cp, nil
	}
	return nil, shared.ErrNotFound
}
