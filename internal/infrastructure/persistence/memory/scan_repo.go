package memory

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ScanRepository is a no-op scan store for dev/tests: scan results are returned
// in the API response and not persisted without a database.
type ScanRepository struct{}

// NewScanRepository returns a no-op scan repository.
func NewScanRepository() *ScanRepository { return &ScanRepository{} }

var _ ports.ScanRepository = (*ScanRepository)(nil)

// SaveScan discards the scan (dev mode has no durable storage); nothing is skipped.
func (ScanRepository) SaveScan(context.Context, shared.ID, *sbom.SBOM, []vulnerability.Vulnerability, ports.ScanSnapshot) (int, error) {
	return 0, nil
}
