package projectuc

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type ProjectMeasureResponse struct {
	Component measure.Node   `json:"component"`
	Children  []measure.Node `json:"children"`
}

// GetMeasures retrieves the measure node and its direct children for a specific path in a project's latest analysis.
func (s *Service) GetMeasures(ctx context.Context, tenantID, projectKey, path string) (ProjectMeasureResponse, error) {
	p, err := s.repo.GetByKey(ctx, shared.ID(tenantID), projectKey)
	if err != nil {
		return ProjectMeasureResponse{}, err // handles ErrNotFound
	}

	analyses, _, err := s.analyses.List(ctx, shared.ID(tenantID), p.ID, 1, time.Time{}, "")
	if err != nil {
		return ProjectMeasureResponse{}, err
	}
	if len(analyses) == 0 {
		return ProjectMeasureResponse{}, shared.ErrNotFound
	}

	latest := analyses[0]
	var targetNode *measure.Node
	var children []measure.Node

	// Find the component and its children
	for _, node := range latest.Snapshot.Nodes {
		if node.Path == path {
			targetNode = &node
		} else if node.Parent == path && (node.Kind == measure.NodeDirectory || node.Kind == measure.NodeFile) {
			// Note: If root path is "", node.Parent is "" for root's children.
			// Wait, root itself has Path="" and Parent="". We must ensure we don't count root as its own child.
			if node.Path != path {
				children = append(children, node)
			}
		}
	}

	if targetNode == nil {
		return ProjectMeasureResponse{}, shared.ErrNotFound
	}

	if children == nil {
		children = []measure.Node{} // ensure non-null json array
	}

	return ProjectMeasureResponse{
		Component: *targetNode,
		Children:  children,
	}, nil
}
