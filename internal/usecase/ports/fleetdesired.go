package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// FleetDesiredStore persists control-plane-owned desired capability sets for canonical host/cluster
// assets. Implementations are tenant-scoped; List is deterministically ordered by AssetID.
//
// Put is compare-and-swap by State.Version: version 1 requires absence, and version N>1 requires the
// stored version to be exactly N-1. Delete removes only expectedVersion; if a newer policy exists it
// returns shared.ErrConflict instead of erasing it. An empty policy is represented by absence.
type FleetDesiredStore interface {
	Get(ctx context.Context, tenantID, assetID shared.ID) (*fleetdesired.State, error)
	Put(ctx context.Context, state *fleetdesired.State) error
	Delete(ctx context.Context, tenantID, assetID shared.ID, expectedVersion int64) error
	List(ctx context.Context, tenantID shared.ID) ([]*fleetdesired.State, error)
}
