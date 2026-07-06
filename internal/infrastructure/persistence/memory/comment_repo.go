package memory

import (
	"context"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// CommentRepository is an in-memory per-finding comment thread (dev/tests).
type CommentRepository struct {
	mu   sync.RWMutex
	data map[shared.ID][]finding.Comment // findingID -> comments (append order)
}

// NewCommentRepository returns an empty in-memory comment repository.
func NewCommentRepository() *CommentRepository {
	return &CommentRepository{data: map[shared.ID][]finding.Comment{}}
}

var _ ports.CommentRepository = (*CommentRepository)(nil)

func (r *CommentRepository) Add(_ context.Context, c finding.Comment) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data[c.FindingID] = append(r.data[c.FindingID], c)
	return nil
}

func (r *CommentRepository) ListByEngagementFinding(_ context.Context, engagementID, findingID shared.ID) ([]finding.Comment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]finding.Comment, 0)
	for _, c := range r.data[findingID] {
		if c.EngagementID == engagementID {
			out = append(out, c)
		}
	}
	return out, nil
}
