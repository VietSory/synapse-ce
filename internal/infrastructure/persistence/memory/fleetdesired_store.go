package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// FleetDesiredStore is the in-memory desired-state store used by development and focused tests.
type FleetDesiredStore struct {
	mu     sync.RWMutex
	states map[string]fleetdesired.State
}

var _ ports.FleetDesiredStore = (*FleetDesiredStore)(nil)

// NewFleetDesiredStore returns an empty store.
func NewFleetDesiredStore() *FleetDesiredStore {
	return &FleetDesiredStore{states: make(map[string]fleetdesired.State)}
}

func fleetDesiredKey(tenantID, agentID shared.ID) string {
	return tenantID.String() + "\x00" + agentID.String()
}

func cloneDesired(state fleetdesired.State) fleetdesired.State {
	state.Capabilities = append([]string(nil), state.Capabilities...)
	return state
}

// Get returns one desired state, or shared.ErrNotFound when none is configured.
func (s *FleetDesiredStore) Get(_ context.Context, tenantID, agentID shared.ID) (*fleetdesired.State, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.states[fleetDesiredKey(tenantID, agentID)]
	if !ok {
		return nil, fmt.Errorf("desired state for agent %s: %w", agentID, shared.ErrNotFound)
	}
	state = cloneDesired(state)
	return &state, nil
}

// Put atomically replaces one agent's current desired state.
func (s *FleetDesiredStore) Put(_ context.Context, state *fleetdesired.State) error {
	if state == nil {
		return fmt.Errorf("%w: nil fleet desired state", shared.ErrValidation)
	}
	if err := state.Validate(); err != nil {
		return err
	}
	stored := cloneDesired(*state)
	key := fleetDesiredKey(state.TenantID, state.AgentID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.states[key]; ok {
		stored.Audit.CreatedAt = current.Audit.CreatedAt
		// The Postgres store preserves created_at on conflict and lets its DB time-order constraint
		// reject an older updated_at. Revalidate after preserving it here so memory mode has the same
		// invariant instead of accepting a state Postgres would refuse.
		if err := stored.Validate(); err != nil {
			return err
		}
	}
	s.states[key] = stored
	return nil
}

// List returns a tenant's desired states ordered by AgentID.
func (s *FleetDesiredStore) List(_ context.Context, tenantID shared.ID) ([]*fleetdesired.State, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*fleetdesired.State, 0)
	for _, state := range s.states {
		if state.TenantID != tenantID {
			continue
		}
		copy := cloneDesired(state)
		out = append(out, &copy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AgentID < out[j].AgentID })
	return out, nil
}
