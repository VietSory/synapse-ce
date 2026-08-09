package ports

import (
	"context"
	"io"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ProjectSourceArtifactPublisher consumes a tar stream supplied by a contributor and publishes
// a server-owned, immutable artifact. allowedPaths comes from the persisted analysis snapshot;
// callers never trust the contributor to choose the durable source inventory.
type ProjectSourceArtifactPublisher interface {
	PublishArchive(ctx context.Context, tenantID, projectID shared.ID, analysisID string, writer projectanalysis.SourceWriter, allowedPaths []string, src io.Reader) (projectanalysis.SourceCapture, error)
}

// ProjectAnalysisSourceMutator is the narrow post-analysis mutation allowed for sanctioned source
// contribution. Implementations must attach source at most once and commit the audit entry with the
// analysis payload atomically where durable transactions are available.
type ProjectAnalysisSourceMutator interface {
	AttachSourceWithAudit(ctx context.Context, tenantID, projectID, analysisID shared.ID, capture projectanalysis.SourceCapture, audit AuditEntry) error
}
