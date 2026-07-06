package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// PlanStore is the in-memory ports.PlanStore (dev/tests). It mirrors the Postgres
// adapter's contract: one plan per session, and SavePlan is an optimistic-concurrency CAS on
// the revision (a stale revision returns ErrConflict). Plans are deep-copied in and out so a
// caller mutating its own Plan value cannot retroactively change stored state.
type PlanStore struct {
	mu     sync.Mutex
	bySess map[shared.ID]agent.Plan
}

// NewPlanStore returns an empty in-memory plan store.
func NewPlanStore() *PlanStore {
	return &PlanStore{bySess: map[shared.ID]agent.Plan{}}
}

var _ ports.PlanStore = (*PlanStore)(nil)

func clonePlan(p agent.Plan) agent.Plan {
	nodes := make([]agent.PlanNode, len(p.Nodes))
	for i, n := range p.Nodes {
		if n.DependsOn != nil {
			deps := make([]string, len(n.DependsOn))
			copy(deps, n.DependsOn)
			n.DependsOn = deps
		}
		nodes[i] = n
	}
	p.Nodes = nodes
	return p
}

func (s *PlanStore) CreatePlan(_ context.Context, p agent.Plan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.bySess[p.SessionID]; exists {
		return fmt.Errorf("plan for session %s already exists: %w", p.SessionID, shared.ErrConflict)
	}
	s.bySess[p.SessionID] = clonePlan(p)
	return nil
}

func (s *PlanStore) GetBySession(_ context.Context, sessionID shared.ID) (agent.Plan, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.bySess[sessionID]
	if !ok {
		return agent.Plan{}, false, nil
	}
	return clonePlan(p), true, nil
}

func (s *PlanStore) SavePlan(_ context.Context, p agent.Plan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.bySess[p.SessionID]
	if !ok {
		return fmt.Errorf("plan for session %s: %w", p.SessionID, shared.ErrNotFound)
	}
	if cur.Revision != p.Revision {
		return fmt.Errorf("plan revision %d is stale (stored %d): %w", p.Revision, cur.Revision, shared.ErrConflict)
	}
	saved := clonePlan(p)
	saved.Revision = p.Revision + 1 // CAS: bump the stored revision
	s.bySess[p.SessionID] = saved
	return nil
}
