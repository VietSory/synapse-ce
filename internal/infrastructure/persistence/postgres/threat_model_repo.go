package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/threatmodel"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ThreatModelRepository persists the architecture-input threat model per engagement to
// PostgreSQL: one row per engagement, the validated domain model stored as a JSONB blob. Tenant-scoped
// customer data (tenant_id recorded for the row-scoping sweep); reads are engagement-scoped (the tenant gate
// runs upstream at the child route).
type ThreatModelRepository struct{ pool *pgxpool.Pool }

// NewThreatModelRepository returns a repository backed by the given pool.
func NewThreatModelRepository(pool *pgxpool.Pool) *ThreatModelRepository {
	return &ThreatModelRepository{pool: pool}
}

var _ ports.ThreatModelStore = (*ThreatModelRepository)(nil)

// Save upserts the engagement's model (the usecase has already bounded size + validated it), bumping version
// on each re-ingest. The model round-trips through the JSONB `data` blob.
func (r *ThreatModelRepository) Save(ctx context.Context, engagementID, tenantID shared.ID, m threatmodel.Model) error {
	blob, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal threat model: %w", err)
	}
	if _, err := r.pool.Exec(ctx,
		`INSERT INTO threat_models (engagement_id, tenant_id, data, version, created_at, updated_at)
		 VALUES ($1, $2, $3, 1, now(), now())
		 ON CONFLICT (engagement_id) DO UPDATE SET data = EXCLUDED.data, version = threat_models.version + 1, updated_at = now()`,
		engagementID.String(), tenantID.String(), blob); err != nil {
		return fmt.Errorf("save threat model: %w", err)
	}
	return nil
}

// Get decodes the engagement's model from its JSONB blob; ok=false when none has been ingested.
func (r *ThreatModelRepository) Get(ctx context.Context, engagementID shared.ID) (threatmodel.Model, bool, error) {
	var blob []byte
	err := r.pool.QueryRow(ctx, `SELECT data FROM threat_models WHERE engagement_id = $1`, engagementID.String()).Scan(&blob)
	if errors.Is(err, pgx.ErrNoRows) {
		return threatmodel.Model{}, false, nil
	}
	if err != nil {
		return threatmodel.Model{}, false, fmt.Errorf("get threat model: %w", err)
	}
	var m threatmodel.Model
	if err := json.Unmarshal(blob, &m); err != nil {
		return threatmodel.Model{}, false, fmt.Errorf("decode threat model: %w", err)
	}
	return m, true, nil
}
