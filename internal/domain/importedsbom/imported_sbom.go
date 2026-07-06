// Package importedsbom models a client-supplied SBOM attached to an engagement.
package importedsbom

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	FormatCycloneDX = "cyclonedx"
	DefaultFilename = "SBOM.json"
)

// Record is the active imported SBOM artifact for an engagement.
type Record struct {
	ID              shared.ID `json:"id"`
	TenantID        shared.ID `json:"tenant_id"`
	EngagementID    shared.ID `json:"engagement_id"`
	Filename        string    `json:"filename"`
	Format          string    `json:"format"`
	SpecVersion     string    `json:"spec_version"`
	TargetRef       string    `json:"target_ref"`
	ComponentCount  int       `json:"component_count"`
	DependencyCount int       `json:"dependency_count"`
	SHA256          string    `json:"sha256"`
	RawJSON         []byte    `json:"-"`
	CreatedBy       string    `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
}

// Metadata returns the safe API/audit representation without raw SBOM content.
func (r Record) Metadata() Metadata {
	return Metadata{
		ID:              r.ID,
		TenantID:        r.TenantID,
		EngagementID:    r.EngagementID,
		Filename:        r.Filename,
		Format:          r.Format,
		SpecVersion:     r.SpecVersion,
		TargetRef:       r.TargetRef,
		ComponentCount:  r.ComponentCount,
		DependencyCount: r.DependencyCount,
		SHA256:          r.SHA256,
		CreatedBy:       r.CreatedBy,
		CreatedAt:       r.CreatedAt,
	}
}

// Validate checks the persisted metadata without inspecting raw JSON semantics.
func (r Record) Validate() error {
	if r.ID.IsZero() {
		return fmt.Errorf("%w: imported SBOM id is required", shared.ErrValidation)
	}
	if r.EngagementID.IsZero() {
		return fmt.Errorf("%w: engagement id is required", shared.ErrValidation)
	}
	if strings.TrimSpace(r.Filename) == "" {
		return fmt.Errorf("%w: filename is required", shared.ErrValidation)
	}
	if r.Format != FormatCycloneDX {
		return fmt.Errorf("%w: unsupported SBOM format %q", shared.ErrValidation, r.Format)
	}
	if strings.TrimSpace(r.SpecVersion) == "" {
		return fmt.Errorf("%w: SBOM spec version is required", shared.ErrValidation)
	}
	if strings.TrimSpace(r.TargetRef) == "" {
		return fmt.Errorf("%w: target ref is required", shared.ErrValidation)
	}
	if r.ComponentCount <= 0 {
		return fmt.Errorf("%w: imported SBOM must contain at least one component", shared.ErrValidation)
	}
	if strings.TrimSpace(r.SHA256) == "" {
		return fmt.Errorf("%w: sha256 is required", shared.ErrValidation)
	}
	if len(r.RawJSON) == 0 {
		return fmt.Errorf("%w: raw SBOM JSON is required", shared.ErrValidation)
	}
	if r.CreatedAt.IsZero() {
		return fmt.Errorf("%w: created_at is required", shared.ErrValidation)
	}
	return nil
}

// Metadata is the safe representation returned to clients.
type Metadata struct {
	ID              shared.ID `json:"id"`
	TenantID        shared.ID `json:"tenant_id"`
	EngagementID    shared.ID `json:"engagement_id"`
	Filename        string    `json:"filename"`
	Format          string    `json:"format"`
	SpecVersion     string    `json:"spec_version"`
	TargetRef       string    `json:"target_ref"`
	ComponentCount  int       `json:"component_count"`
	DependencyCount int       `json:"dependency_count"`
	SHA256          string    `json:"sha256"`
	CreatedBy       string    `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
}
