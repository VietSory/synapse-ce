package memory

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// GetAssetByID returns one canonical technical asset by server-issued ID. It is intentionally a
// narrow extension used by desired-state admission; the broad AssetRepository contract remains keyed
// by natural identity for normal observation/upsert flows. Invalid identifiers are validation errors;
// a valid but absent/cross-tenant asset is reported as ErrNotFound.
func (s *AssetStore) GetAssetByID(_ context.Context, tenantID, id shared.ID) (*asset.Asset, error) {
	if tenantID.IsZero() || id.IsZero() {
		return nil, fmt.Errorf("%w: asset id lookup needs tenant and id", shared.ErrValidation)
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
