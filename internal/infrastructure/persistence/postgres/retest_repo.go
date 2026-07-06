package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// RetestRepository persists the per-finding retest history to PostgreSQL.
type RetestRepository struct{ pool *pgxpool.Pool }

// NewRetestRepository returns a repository backed by the given pool.
func NewRetestRepository(pool *pgxpool.Pool) *RetestRepository {
	return &RetestRepository{pool: pool}
}

var _ ports.RetestRepository = (*RetestRepository)(nil)

// Add inserts a retest (append-only; retests are not edited or deleted in app code).
func (r *RetestRepository) Add(ctx context.Context, rt finding.Retest) error {
	if _, err := r.pool.Exec(ctx,
		`INSERT INTO finding_retests (id, tenant_id, engagement_id, finding_id, outcome, note, tester, created_at)
		 VALUES ($1, '', $2, $3, $4, $5, $6, $7)`,
		rt.ID.String(), rt.EngagementID.String(), rt.FindingID.String(), string(rt.Outcome), rt.Note, rt.Tester, rt.At); err != nil {
		return fmt.Errorf("insert retest: %w", err)
	}
	return nil
}

// ListByEngagementFinding returns a finding's retests oldest-first, scoped to the
// engagement (no cross-engagement read).
func (r *RetestRepository) ListByEngagementFinding(ctx context.Context, engagementID, findingID shared.ID) ([]finding.Retest, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, engagement_id, finding_id, outcome, note, tester, created_at
		 FROM finding_retests WHERE finding_id=$1 AND engagement_id=$2 ORDER BY created_at ASC, id ASC`,
		findingID.String(), engagementID.String())
	if err != nil {
		return nil, fmt.Errorf("list retests: %w", err)
	}
	defer rows.Close()
	out := make([]finding.Retest, 0)
	for rows.Next() {
		var (
			rt           finding.Retest
			id, eid, fid string
			outcome      string
		)
		if err := rows.Scan(&id, &eid, &fid, &outcome, &rt.Note, &rt.Tester, &rt.At); err != nil {
			return nil, fmt.Errorf("scan retest: %w", err)
		}
		rt.ID, rt.EngagementID, rt.FindingID = shared.ID(id), shared.ID(eid), shared.ID(fid)
		rt.Outcome = finding.RetestOutcome(outcome)
		out = append(out, rt)
	}
	return out, rows.Err()
}
