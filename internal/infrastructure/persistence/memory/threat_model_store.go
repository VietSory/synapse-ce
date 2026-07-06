package memory

import (
	"context"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/threatmodel"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ThreatModelStore is the in-memory architecture-input threat-model store (dev/tests, mirrors the
// Postgres adapter): one model per engagement, replaced on each Save (re-syncable, not append-only). Reads
// are engagement-scoped (the tenant gate runs upstream at the child route).
type ThreatModelStore struct {
	mu    sync.RWMutex
	byEng map[shared.ID]threatmodel.Model
}

// NewThreatModelStore returns an empty in-memory threat-model store.
func NewThreatModelStore() *ThreatModelStore {
	return &ThreatModelStore{byEng: map[shared.ID]threatmodel.Model{}}
}

var _ ports.ThreatModelStore = (*ThreatModelStore)(nil)

// Save upserts the engagement's model (tenant id unused in memory; the Postgres adapter persists it).
func (s *ThreatModelStore) Save(_ context.Context, engagementID, _ shared.ID, m threatmodel.Model) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byEng[engagementID] = m
	return nil
}

// Get returns the engagement's model, ok=false when none has been ingested.
func (s *ThreatModelStore) Get(_ context.Context, engagementID shared.ID) (threatmodel.Model, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.byEng[engagementID]
	return m, ok, nil
}
