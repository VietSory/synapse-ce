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

type fleetDesiredStoreKey struct {
	tenantID shared.ID
	assetID  shared.ID
}

// FleetDesiredStore is the in-memory desired-state store used by development and focused tests.
type FleetDesiredStore struct {
	mu     sync.RWMutex
	states map[fleetDesiredStoreKey]fleetdesired.State
}

var _ ports.FleetDesiredStore = (*FleetDesiredStore)(nil)

// NewFleetDesiredStore returns an empty store.
func NewFleetDesiredStore() *FleetDesiredStore {
	return &FleetDesiredStore{states: make(map[fleetDesiredStoreKey]fleetdesired.State)}
}

func cloneDesired(state fleetdesired.State) fleetdesired.State {
	state.Capabilities = append([]string(nil), state.Capabilities...)
	return state
}

// Get returns one asset's desired state, or shared.ErrNotFound when none is configured.
func (s *FleetDesiredStore) Get(_ context.Context, tenantID, assetID shared.ID) (*fleetdesired.State, error) {
	if tenantID.IsZero() || assetID.IsZero() {
		return nil, fmt.Errorf("%w: desired-state lookup needs tenant and asset", shared.ErrValidation)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.states[fleetDesiredStoreKey{tenantID: tenantID, assetID: assetID}]
	if !ok {
		return nil, fmt.Errorf("desired state for asset %s: %w", assetID, shared.ErrNotFound)
	}
	state = cloneDesired(state)
	return &state, nil
}

// Put stores one CAS version. Version 1 creates an absent row; later versions must be exactly one
// greater than the stored version. A stale concurrent writer therefore fails with ErrConflict instead
// of silently replacing a newer operator decision.
func (s *FleetDesiredStore) Put(_ context.Context, state *fleetdesired.State) error {
	if state == nil {
		return fmt.Errorf("%w: nil fleet desired state", shared.ErrValidation)
	}
	if err := state.Validate(); err != nil {
		return err
	}
	stored := cloneDesired(*state)
	key := fleetDesiredStoreKey{tenantID: state.TenantID, assetID: state.AssetID}

	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.states[key]
	if !exists {
		if stored.Version != 1 {
			return fmt.Errorf("%w: desired state for asset %s is absent; create requires version 1", shared.ErrConflict, state.AssetID)
		}
		s.states[key] = stored
		return nil
	}
	if current.Version == 1<<63-1 {
		return fmt.Errorf("%w: desired state version exhausted for asset %s", shared.ErrConflict, state.AssetID)
	}
	if stored.Version != current.Version+1 {
		return fmt.Errorf("%w: desired state version %d does not follow stored version %d for asset %s",
			shared.ErrConflict, stored.Version, current.Version, state.AssetID)
	}
	stored.Audit.CreatedAt = current.Audit.CreatedAt
	if err := stored.Validate(); err != nil {
		return err
	}
	s.states[key] = stored
	return nil
}

// Delete clears one asset's desired policy only if expectedVersion is still current. Absence is an
// idempotent success; a newer concurrent policy returns ErrConflict and is never erased.
func (s *FleetDesiredStore) Delete(_ context.Context, tenantID, assetID shared.ID, expectedVersion int64) error {
	if tenantID.IsZero() || assetID.IsZero() || expectedVersion < 1 {
		return fmt.Errorf("%w: desired-state delete needs tenant, asset and positive expected version", shared.ErrValidation)
	}
	key := fleetDesiredStoreKey{tenantID: tenantID, assetID: assetID}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.states[key]
	if !exists {
		return nil
	}
	if current.Version != expectedVersion {
		return fmt.Errorf("%w: desired state version changed from %d to %d for asset %s",
			shared.ErrConflict, expectedVersion, current.Version, assetID)
	}
	delete(s.states, key)
	return nil
}

// List returns a tenant's desired states ordered by canonical AssetID.
func (s *FleetDesiredStore) List(_ context.Context, tenantID shared.ID) ([]*fleetdesired.State, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: desired-state list needs a tenant", shared.ErrValidation)
	}
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
	sort.Slice(out, func(i, j int) bool { return out[i].AssetID < out[j].AssetID })
	return out, nil
}
