package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// FleetDesiredStore persists control-plane-owned desired capability sets for canonical host/cluster
// assets. Implementations are tenant-scoped; List is deterministically ordered by AssetID.
//
// An empty policy is represented by absence, not a row with an empty capability array. Delete is
// therefore part of the contract and must be idempotent.
type FleetDesiredStore interface {
	Get(ctx context.Context, tenantID, assetID shared.ID) (*fleetdesired.State, error)
	Put(ctx context.Context, state *fleetdesired.State) error
	Delete(ctx context.Context, tenantID, assetID shared.ID) error
	List(ctx context.Context, tenantID shared.ID) ([]*fleetdesired.State, error)
}
