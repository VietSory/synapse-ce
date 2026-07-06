package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ScanResultStore is an in-memory cache of the latest scan result per engagement.
type ScanResultStore struct {
	mu   sync.RWMutex
	data map[shared.ID][]byte
}

// NewScanResultStore returns an empty in-memory scan-result store.
func NewScanResultStore() *ScanResultStore { return &ScanResultStore{data: map[shared.ID][]byte{}} }

var _ ports.ScanResultStore = (*ScanResultStore)(nil)

// SaveResult stores a copy of the engagement's latest scan result JSON.
func (s *ScanResultStore) SaveResult(_ context.Context, engagementID shared.ID, result []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(result))
	copy(cp, result)
	s.data[engagementID] = cp
	return nil
}

// LatestResult returns the cached scan result, or shared.ErrNotFound.
func (s *ScanResultStore) LatestResult(_ context.Context, engagementID shared.ID) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.data[engagementID]
	if !ok {
		return nil, fmt.Errorf("scan result for %s: %w", engagementID, shared.ErrNotFound)
	}
	cp := make([]byte, len(d)) // copy-on-read: never hand out the internal slice
	copy(cp, d)
	return cp, nil
}
