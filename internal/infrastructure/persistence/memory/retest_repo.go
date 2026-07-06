package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// RetestRepository is an in-memory ports.RetestRepository for dev/tests.
type RetestRepository struct {
	mu   sync.Mutex
	rows []finding.Retest
}

// NewRetestRepository returns an empty in-memory retest store.
func NewRetestRepository() *RetestRepository { return &RetestRepository{} }

var _ ports.RetestRepository = (*RetestRepository)(nil)

// Add appends a retest.
func (r *RetestRepository) Add(_ context.Context, rt finding.Retest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows = append(r.rows, rt)
	return nil
}

// ListByEngagementFinding returns a finding's retests oldest-first, engagement-scoped.
func (r *RetestRepository) ListByEngagementFinding(_ context.Context, engagementID, findingID shared.ID) ([]finding.Retest, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []finding.Retest{}
	for _, rt := range r.rows {
		if rt.FindingID == findingID && rt.EngagementID == engagementID {
			out = append(out, rt)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, nil
}
