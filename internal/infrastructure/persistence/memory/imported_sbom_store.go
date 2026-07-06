package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importedsbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ImportedSBOMStore keeps the active imported SBOM per engagement in memory.
type ImportedSBOMStore struct {
	mu   sync.RWMutex
	data map[string]importedsbom.Record
}

// NewImportedSBOMStore returns an empty imported-SBOM store.
func NewImportedSBOMStore() *ImportedSBOMStore {
	return &ImportedSBOMStore{data: map[string]importedsbom.Record{}}
}

var _ ports.ImportedSBOMStore = (*ImportedSBOMStore)(nil)

// SaveActive stores a copy of the active imported SBOM for its engagement.
func (s *ImportedSBOMStore) SaveActive(_ context.Context, record importedsbom.Record) error {
	if err := record.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[activeSBOMKey(record.TenantID, record.EngagementID)] = copyImportedSBOM(record)
	return nil
}

// LatestByEngagement returns a copy of the active imported SBOM.
func (s *ImportedSBOMStore) LatestByEngagement(_ context.Context, tenantID, engagementID shared.ID) (importedsbom.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.data[activeSBOMKey(tenantID, engagementID)]
	if !ok {
		return importedsbom.Record{}, fmt.Errorf("imported SBOM for engagement %s: %w", engagementID, shared.ErrNotFound)
	}
	return copyImportedSBOM(record), nil
}

func activeSBOMKey(tenantID, engagementID shared.ID) string {
	return tenantID.String() + "\x00" + engagementID.String()
}

func copyImportedSBOM(record importedsbom.Record) importedsbom.Record {
	cp := record
	cp.RawJSON = append([]byte(nil), record.RawJSON...)
	return cp
}
