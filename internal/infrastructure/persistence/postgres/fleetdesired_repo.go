package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const fleetDesiredCols = `tenant_id, agent_id, capabilities, updated_by, created_at, updated_at`

// FleetDesiredRepository persists operator-owned desired state (migration 0107). Every operation is
// tenant-scoped through WithTenant so the RLS boundary is identical to the fleet agent identity store.
type FleetDesiredRepository struct{ pool *pgxpool.Pool }

// NewFleetDesiredRepository constructs the Postgres desired-state repository.
func NewFleetDesiredRepository(pool *pgxpool.Pool) *FleetDesiredRepository {
	return &FleetDesiredRepository{pool: pool}
}

var _ ports.FleetDesiredStore = (*FleetDesiredRepository)(nil)

// Get returns one agent's desired state, or shared.ErrNotFound when none is configured.
func (r *FleetDesiredRepository) Get(ctx context.Context, tenantID, agentID shared.ID) (*fleetdesired.State, error) {
	var state fleetdesired.State
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var tenant, agent, updatedBy string
		if scanErr := tx.QueryRow(ctx, `SELECT `+fleetDesiredCols+` FROM fleet_desired_state WHERE tenant_id=$1 AND agent_id=$2`,
			tenantID.String(), agentID.String()).Scan(&tenant, &agent, &state.Capabilities, &updatedBy, &state.Audit.CreatedAt, &state.Audit.UpdatedAt); scanErr != nil {
			return scanErr
		}
		state.TenantID = shared.ID(tenant)
		state.AgentID = shared.ID(agent)
		state.UpdatedBy = shared.ID(updatedBy)
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("desired state for agent %s: %w", agentID, shared.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get fleet desired state: %w", err)
	}
	return &state, nil
}

// Put atomically replaces one agent's desired capability array. created_at is deliberately preserved
// on conflict; updated_at and attribution move with the operator's latest decision.
func (r *FleetDesiredRepository) Put(ctx context.Context, state *fleetdesired.State) error {
	if state == nil {
		return fmt.Errorf("%w: nil fleet desired state", shared.ErrValidation)
	}
	if err := state.Validate(); err != nil {
		return err
	}
	caps := state.Capabilities
	if caps == nil {
		caps = []string{}
	}
	err := WithTenant(ctx, r.pool, state.TenantID.String(), func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, `
			INSERT INTO fleet_desired_state (`+fleetDesiredCols+`)
			VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (tenant_id, agent_id) DO UPDATE SET
			  capabilities = EXCLUDED.capabilities,
			  updated_by   = EXCLUDED.updated_by,
			  updated_at   = EXCLUDED.updated_at`,
			state.TenantID.String(), state.AgentID.String(), caps, state.UpdatedBy.String(), state.Audit.CreatedAt, state.Audit.UpdatedAt)
		return execErr
	})
	if err != nil {
		return fmt.Errorf("store fleet desired state: %w", err)
	}
	return nil
}

// List returns a tenant's desired states ordered by canonical AgentID.
func (r *FleetDesiredRepository) List(ctx context.Context, tenantID shared.ID) ([]*fleetdesired.State, error) {
	var out []*fleetdesired.State
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, queryErr := tx.Query(ctx, `SELECT `+fleetDesiredCols+` FROM fleet_desired_state WHERE tenant_id=$1 ORDER BY agent_id`, tenantID.String())
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()
		for rows.Next() {
			var state fleetdesired.State
			var tenant, agent, updatedBy string
			if scanErr := rows.Scan(&tenant, &agent, &state.Capabilities, &updatedBy, &state.Audit.CreatedAt, &state.Audit.UpdatedAt); scanErr != nil {
				return scanErr
			}
			state.TenantID = shared.ID(tenant)
			state.AgentID = shared.ID(agent)
			state.UpdatedBy = shared.ID(updatedBy)
			out = append(out, &state)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list fleet desired states: %w", err)
	}
	return out, nil
}
