package memory

import (
	"context"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// DecisionStore is the in-memory ports.DecisionStore (dev/tests). It mirrors the
// Postgres adapter: a monotonic per-session seq, idempotent on (session_id, action_id) for step
// decisions and a single stop per session (a re-record is a no-op, so a redelivered drive
// cannot fork the log).
type DecisionStore struct {
	mu     sync.Mutex
	bySess map[shared.ID][]agent.AgentDecision
}

// NewDecisionStore returns an empty in-memory decision store.
func NewDecisionStore() *DecisionStore {
	return &DecisionStore{bySess: map[shared.ID][]agent.AgentDecision{}}
}

var _ ports.DecisionStore = (*DecisionStore)(nil)

func (s *DecisionStore) AppendDecision(_ context.Context, d agent.AgentDecision) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing := s.bySess[d.SessionID]
	for _, e := range existing {
		// Idempotency: a step is keyed by its action id; a stop is unique per session.
		if d.Kind == agent.DecisionStep && e.Kind == agent.DecisionStep && d.ActionID != "" && e.ActionID == d.ActionID {
			return nil
		}
		if d.Kind == agent.DecisionStop && e.Kind == agent.DecisionStop {
			return nil
		}
	}
	d.Seq = len(existing)
	s.bySess[d.SessionID] = append(existing, d)
	return nil
}

func (s *DecisionStore) ListBySession(_ context.Context, sessionID shared.ID) ([]agent.AgentDecision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.bySess[sessionID]
	out := make([]agent.AgentDecision, len(src))
	copy(out, src) // ordered by seq (append order)
	return out, nil
}
