package ports

import (
	"context"
	"io"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const ProjectSourcePublishAuditAction = "project.source.publish"

// ProjectSourceArtifactPublisher consumes a tar stream supplied by a contributor and publishes
// a server-owned, immutable artifact. allowedPaths comes from the persisted analysis snapshot;
// callers never trust the contributor to choose the durable source inventory.
type ProjectSourceArtifactPublisher interface {
	PublishArchive(ctx context.Context, tenantID, projectID shared.ID, analysisID string, writer projectanalysis.SourceWriter, allowedPaths []string, src io.Reader) (projectanalysis.SourceCapture, error)
	// DiscardPublished removes only the v2 artifact claimed by PublishArchive. It is a narrow
	// compensation hook for a failed DB+audit commit and must not delete legacy capture paths.
	DiscardPublished(ctx context.Context, tenantID, projectID shared.ID, analysisID string) error
}

// ProjectAnalysisSourceAttacher is the narrow post-analysis mutation allowed for sanctioned
// source contribution. Implementations must attach source at most once.
type ProjectAnalysisSourceAttacher interface {
	AttachSource(ctx context.Context, tenantID, projectID, analysisID shared.ID, capture projectanalysis.SourceCapture) error
}

// ProjectAnalysisSourceAtomicMutator combines source attachment and its audit entry in one durable
// transaction. Production stores should implement this; the use case requires this interface so
// durable publication can never acknowledge source metadata without its matching audit record.
type ProjectAnalysisSourceAtomicMutator interface {
	AttachSourceWithAudit(ctx context.Context, tenantID, projectID, analysisID shared.ID, capture projectanalysis.SourceCapture, audit AuditEntry) error
}
