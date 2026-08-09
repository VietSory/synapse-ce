package memory

import (
	"context"
	"fmt"
	"slices"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepolicy"
)

// AttachSource supports in-process tests and ephemeral stores, but the in-memory store deliberately
// does not satisfy the sanctioned publish mutator contract because it cannot append a durable audit
// record in the same transaction. Production PublishSource therefore fails closed without Postgres.
func (s *ProjectAnalysisStore) AttachSource(_ context.Context, tenantID, projectID, analysisID shared.ID, capture projectanalysis.SourceCapture) error {
	if tenantID.IsZero() || projectID.IsZero() || analysisID.IsZero() {
		return fmt.Errorf("%w: source attachment scope is required", shared.ErrValidation)
	}
	if !capture.Capabilities.Source.Available || capture.Manifest.Writer == nil || capture.Manifest.Digest == "" || capture.Manifest.Digest != capture.Manifest.ArtifactDigest() {
		return fmt.Errorf("%w: published source capture is invalid", shared.ErrValidation)
	}
	if err := capture.Manifest.Writer.Validate(); err != nil {
		return fmt.Errorf("%w: %v", shared.ErrValidation, err)
	}
	for _, file := range capture.Manifest.Files {
		if err := file.Validate(); err != nil {
			return fmt.Errorf("%w: %v", shared.ErrValidation, err)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data {
		analysis := &s.data[i].analysis
		if analysis.ID != analysisID.String() || analysis.ProjectID != projectID.String() || analysis.TenantID != tenantID.String() {
			continue
		}
		if analysis.Capabilities.Source.Available || analysis.SourceManifest.Digest != "" || len(analysis.SourceManifest.Files) != 0 || analysis.SourceManifest.Writer != nil {
			return shared.ErrConflict
		}
		allowed := make(map[string]struct{})
		for _, node := range analysis.Snapshot.Nodes {
			if node.Kind == measure.NodeFile && sourcepolicy.RetainPath(node.Path) {
				allowed[node.Path] = struct{}{}
			}
		}
		seen := make(map[string]struct{}, len(capture.Manifest.Files))
		for _, file := range capture.Manifest.Files {
			if _, ok := allowed[file.Path]; !ok {
				return fmt.Errorf("%w: published source path is not part of the analysis snapshot", shared.ErrValidation)
			}
			if _, duplicate := seen[file.Path]; duplicate {
				return fmt.Errorf("%w: duplicate published source path", shared.ErrValidation)
			}
			seen[file.Path] = struct{}{}
		}
		manifest := capture.Manifest
		manifest.Files = slices.Clone(capture.Manifest.Files)
		writer := *capture.Manifest.Writer
		manifest.Writer = &writer
		analysis.SourceManifest = manifest
		analysis.Capabilities.Source = projectanalysis.Capability{Available: true}
		analysis.Capabilities.Highlighting = projectanalysis.Capability{Available: true}
		return nil
	}
	return shared.ErrNotFound
}
