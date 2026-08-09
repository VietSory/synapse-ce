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

// ProjectAnalysisSourceAttacher is the narrow post-analysis mutation allowed for sanctioned
// source contribution. Implementations must attach source at most once.
type ProjectAnalysisSourceAttacher interface {
	AttachSource(ctx context.Context, tenantID, projectID, analysisID shared.ID, capture projectanalysis.SourceCapture) error
}

// ProjectAnalysisSourceAtomicMutator combines source attachment and its audit entry in one durable
// transaction. Production stores should implement this; the use case falls back to Attacher plus
// AuditLogger only for stores that cannot provide transactional durability (for example memory tests).
type ProjectAnalysisSourceAtomicMutator interface {
	AttachSourceWithAudit(ctx context.Context, tenantID, projectID, analysisID shared.ID, capture projectanalysis.SourceCapture, audit AuditEntry) error
}
