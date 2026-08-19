package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// FleetDesiredStore persists the control-plane-owned desired capability set for each canonical
// AgentID. Implementations are tenant-scoped; List is deterministically ordered by agent id.
type FleetDesiredStore interface {
	Get(ctx context.Context, tenantID, agentID shared.ID) (*fleetdesired.State, error)
	Put(ctx context.Context, state *fleetdesired.State) error
	List(ctx context.Context, tenantID shared.ID) ([]*fleetdesired.State, error)
}
