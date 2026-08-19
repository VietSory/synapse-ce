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

const fleetDesiredCols = `tenant_id, asset_id, capabilities, updated_by, version, created_at, updated_at`

// FleetDesiredRepository persists operator-owned desired state (migration 0107). Every operation is
// tenant-scoped through WithTenant so PostgreSQL RLS is the final isolation boundary.
type FleetDesiredRepository struct{ pool *pgxpool.Pool }

// NewFleetDesiredRepository constructs the Postgres desired-state repository.
func NewFleetDesiredRepository(pool *pgxpool.Pool) *FleetDesiredRepository {
	return &FleetDesiredRepository{pool: pool}
}

var _ ports.FleetDesiredStore = (*FleetDesiredRepository)(nil)

// Get returns one canonical asset's desired state, or shared.ErrNotFound when none is configured.
func (r *FleetDesiredRepository) Get(ctx context.Context, tenantID, assetID shared.ID) (*fleetdesired.State, error) {
	if tenantID.IsZero() || assetID.IsZero() {
		return nil, fmt.Errorf("%w: desired-state lookup needs tenant and asset", shared.ErrValidation)
	}
	var state *fleetdesired.State
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var scanErr error
		state, scanErr = scanFleetDesired(tx.QueryRow(ctx,
			`SELECT `+fleetDesiredCols+` FROM fleet_desired_state WHERE tenant_id=$1 AND asset_id=$2`,
			tenantID.String(), assetID.String()))
		return scanErr
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("desired state for asset %s: %w", assetID, shared.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get fleet desired state: %w", err)
	}
	if state.TenantID != tenantID || state.AssetID != assetID {
		return nil, fmt.Errorf("%w: desired-state query returned identity %s/%s, want %s/%s",
			shared.ErrValidation, state.TenantID, state.AssetID, tenantID, assetID)
	}
	return state, nil
}

// Put stores one CAS version. Version 1 creates an absent row. Version N>1 updates only version N-1;
// a stale writer gets shared.ErrConflict instead of silently replacing a newer policy. Subject
// admission (canonical host/cluster) belongs to the use case; the database FK independently guarantees
// that a newly created desired row references a technical asset in the same tenant.
func (r *FleetDesiredRepository) Put(ctx context.Context, state *fleetdesired.State) error {
	if state == nil {
		return fmt.Errorf("%w: nil fleet desired state", shared.ErrValidation)
	}
	if err := state.Validate(); err != nil {
		return err
	}
	err := WithTenant(ctx, r.pool, state.TenantID.String(), func(tx pgx.Tx) error {
		if state.Version == 1 {
			var insertedVersion int64
			err := tx.QueryRow(ctx, `
				INSERT INTO fleet_desired_state (`+fleetDesiredCols+`)
				VALUES ($1,$2,$3,$4,$5,$6,$7)
				ON CONFLICT (tenant_id, asset_id) DO NOTHING
				RETURNING version`,
				state.TenantID.String(), state.AssetID.String(), state.Capabilities, state.UpdatedBy.String(),
				state.Version, state.Audit.CreatedAt, state.Audit.UpdatedAt).Scan(&insertedVersion)
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: desired state for asset %s already exists", shared.ErrConflict, state.AssetID)
			}
			return err
		}

		tag, err := tx.Exec(ctx, `
			UPDATE fleet_desired_state
			SET capabilities=$3, updated_by=$4, version=$5, updated_at=$6
			WHERE tenant_id=$1 AND asset_id=$2 AND version=$7`,
			state.TenantID.String(), state.AssetID.String(), state.Capabilities, state.UpdatedBy.String(),
			state.Version, state.Audit.UpdatedAt, state.Version-1)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: desired state for asset %s no longer has version %d",
				shared.ErrConflict, state.AssetID, state.Version-1)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("store fleet desired state: %w", err)
	}
	return nil
}

// Delete clears one asset's desired policy only if expectedVersion is still current. If the row is
// already absent it is an idempotent success; if a newer row exists it returns shared.ErrConflict.
func (r *FleetDesiredRepository) Delete(ctx context.Context, tenantID, assetID shared.ID, expectedVersion int64) error {
	if tenantID.IsZero() || assetID.IsZero() || expectedVersion < 1 {
		return fmt.Errorf("%w: desired-state delete needs tenant, asset and positive expected version", shared.ErrValidation)
	}
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`DELETE FROM fleet_desired_state WHERE tenant_id=$1 AND asset_id=$2 AND version=$3`,
			tenantID.String(), assetID.String(), expectedVersion)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 {
			return nil
		}
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM fleet_desired_state WHERE tenant_id=$1 AND asset_id=$2)`,
			tenantID.String(), assetID.String()).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("%w: desired state for asset %s changed after version %d",
				shared.ErrConflict, assetID, expectedVersion)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("delete fleet desired state: %w", err)
	}
	return nil
}

// List returns a tenant's desired states ordered by canonical AssetID. Every scanned row is validated
// before it leaves infrastructure so manually-corrupted policy fails closed at the storage boundary.
func (r *FleetDesiredRepository) List(ctx context.Context, tenantID shared.ID) ([]*fleetdesired.State, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: desired-state list needs a tenant", shared.ErrValidation)
	}
	out := make([]*fleetdesired.State, 0)
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, queryErr := tx.Query(ctx,
			`SELECT `+fleetDesiredCols+` FROM fleet_desired_state WHERE tenant_id=$1 ORDER BY asset_id`, tenantID.String())
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()
		for rows.Next() {
			state, scanErr := scanFleetDesired(rows)
			if scanErr != nil {
				return scanErr
			}
			if state.TenantID != tenantID {
				return fmt.Errorf("%w: desired-state list returned tenant %s, want %s",
					shared.ErrValidation, state.TenantID, tenantID)
			}
			out = append(out, state)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list fleet desired states: %w", err)
	}
	return out, nil
}

func scanFleetDesired(row rowScanner) (*fleetdesired.State, error) {
	var (
		state                      fleetdesired.State
		tenant, assetID, updatedBy string
	)
	if err := row.Scan(&tenant, &assetID, &state.Capabilities, &updatedBy, &state.Version,
		&state.Audit.CreatedAt, &state.Audit.UpdatedAt); err != nil {
		return nil, err
	}
	state.TenantID = shared.ID(tenant)
	state.AssetID = shared.ID(assetID)
	state.UpdatedBy = shared.ID(updatedBy)
	if err := state.Validate(); err != nil {
		return nil, fmt.Errorf("invalid stored fleet desired state: %w", err)
	}
	return &state, nil
}
