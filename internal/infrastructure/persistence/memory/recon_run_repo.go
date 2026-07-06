package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/recon"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ReconRunRepository is an in-memory ports.ReconRunStore for dev/tests.
type ReconRunRepository struct {
	mu   sync.Mutex
	byID map[shared.ID]recon.Run
}

// NewReconRunRepository returns an empty in-memory recon-run store.
func NewReconRunRepository() *ReconRunRepository {
	return &ReconRunRepository{byID: map[shared.ID]recon.Run{}}
}

var _ ports.ReconRunStore = (*ReconRunRepository)(nil)

// Save upserts a run.
func (r *ReconRunRepository) Save(_ context.Context, run recon.Run) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID[run.ID] = run
	return nil
}

// Get returns a run by id, or shared.ErrNotFound.
func (r *ReconRunRepository) Get(_ context.Context, id shared.ID) (recon.Run, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	run, ok := r.byID[id]
	if !ok {
		return recon.Run{}, fmt.Errorf("recon run %s: %w", id, shared.ErrNotFound)
	}
	return run, nil
}

// ListByEngagement returns an engagement's runs, newest first.
func (r *ReconRunRepository) ListByEngagement(_ context.Context, engagementID shared.ID) ([]recon.Run, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []recon.Run{}
	for _, run := range r.byID {
		if run.EngagementID == engagementID {
			out = append(out, run)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out, nil
}

// ListStaleRunning returns runs still 'running' that started before olderThan (≤ limit),
// oldest first.
func (r *ReconRunRepository) ListStaleRunning(_ context.Context, olderThan time.Time, limit int) ([]recon.Run, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []recon.Run{}
	for _, run := range r.byID {
		if run.Status == recon.StatusRunning && run.StartedAt.Before(olderThan) {
			out = append(out, run)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.Before(out[j].StartedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
