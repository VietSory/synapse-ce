package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ScanResultStore caches the latest full scan result (JSON) per engagement.
type ScanResultStore struct{ pool *pgxpool.Pool }

// NewScanResultStore returns a store backed by the given pool.
func NewScanResultStore(pool *pgxpool.Pool) *ScanResultStore { return &ScanResultStore{pool: pool} }

var _ ports.ScanResultStore = (*ScanResultStore)(nil)

// SaveResult upserts the engagement's latest scan result JSON.
func (r *ScanResultStore) SaveResult(ctx context.Context, engagementID shared.ID, result []byte) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO scan_results (engagement_id, result, created_at) VALUES ($1, $2, now())
		 ON CONFLICT (engagement_id) DO UPDATE SET result = EXCLUDED.result, created_at = EXCLUDED.created_at`,
		engagementID.String(), result)
	if err != nil {
		return fmt.Errorf("save scan result: %w", err)
	}
	return nil
}

// LatestResult returns the engagement's cached scan result, or shared.ErrNotFound.
func (r *ScanResultStore) LatestResult(ctx context.Context, engagementID shared.ID) ([]byte, error) {
	var data []byte
	err := r.pool.QueryRow(ctx, `SELECT result FROM scan_results WHERE engagement_id=$1`, engagementID.String()).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("scan result for %s: %w", engagementID, shared.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("load scan result: %w", err)
	}
	return data, nil
}
