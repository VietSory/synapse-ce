package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// CommentRepository persists the per-finding comment thread to PostgreSQL.
type CommentRepository struct{ pool *pgxpool.Pool }

// NewCommentRepository returns a repository backed by the given pool.
func NewCommentRepository(pool *pgxpool.Pool) *CommentRepository {
	return &CommentRepository{pool: pool}
}

var _ ports.CommentRepository = (*CommentRepository)(nil)

// Add inserts a comment (append-only; comments are not edited or deleted in app code).
func (r *CommentRepository) Add(ctx context.Context, c finding.Comment) error {
	if _, err := r.pool.Exec(ctx,
		`INSERT INTO finding_comments (id, tenant_id, engagement_id, finding_id, author, body, created_at)
		 VALUES ($1, '', $2, $3, $4, $5, $6)`,
		c.ID.String(), c.EngagementID.String(), c.FindingID.String(), c.Author, c.Body, c.CreatedAt); err != nil {
		return fmt.Errorf("insert comment: %w", err)
	}
	return nil
}

// ListByEngagementFinding returns a finding's comments oldest-first, scoped to the
// engagement (no cross-engagement read).
func (r *CommentRepository) ListByEngagementFinding(ctx context.Context, engagementID, findingID shared.ID) ([]finding.Comment, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, engagement_id, finding_id, author, body, created_at
		 FROM finding_comments WHERE finding_id=$1 AND engagement_id=$2 ORDER BY created_at ASC, id ASC`,
		findingID.String(), engagementID.String())
	if err != nil {
		return nil, fmt.Errorf("list comments: %w", err)
	}
	defer rows.Close()
	out := make([]finding.Comment, 0)
	for rows.Next() {
		var (
			c            finding.Comment
			id, eid, fid string
		)
		if err := rows.Scan(&id, &eid, &fid, &c.Author, &c.Body, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan comment: %w", err)
		}
		c.ID, c.EngagementID, c.FindingID = shared.ID(id), shared.ID(eid), shared.ID(fid)
		out = append(out, c)
	}
	return out, rows.Err()
}
