package memory

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/hotspot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.ProjectHotspotStore = (*ProjectAnalysisStore)(nil)
var _ ports.ProjectAnalysisProjectionStore = (*ProjectAnalysisStore)(nil)

func (s *ProjectAnalysisStore) ListHotspots(ctx context.Context, tenantID, projectID shared.ID, filter hotspot.ListFilter) (hotspot.Page, error) {
	if err := ctx.Err(); err != nil {
		return hotspot.Page{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]hotspot.Hotspot, 0)
	for _, item := range s.hotspots {
		if item.TenantID != tenantID || item.ProjectID != projectID || !matches(item, filter) {
			continue
		}
		items = append(items, cloneHotspot(item))
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].LastSeenAt.Equal(items[j].LastSeenAt) {
			return items[i].ID > items[j].ID
		}
		return items[i].LastSeenAt.After(items[j].LastSeenAt)
	})
	page := hotspot.Page{Facets: facets(items)}
	if !filter.BeforeLastSeenAt.IsZero() {
		items = afterCursor(items, filter.BeforeLastSeenAt, filter.BeforeID)
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 25
	}
	page.Items = items
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.Next = &hotspot.Cursor{BeforeLastSeenAt: last.LastSeenAt, BeforeID: last.ID}
	}
	return page, nil
}

func (s *ProjectAnalysisStore) GetHotspot(ctx context.Context, tenantID, projectID, hotspotID shared.ID) (hotspot.Hotspot, error) {
	if err := ctx.Err(); err != nil {
		return hotspot.Hotspot{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, item := range s.hotspots {
		if item.TenantID == tenantID && item.ProjectID == projectID && item.ID == hotspotID {
			return cloneHotspot(item), nil
		}
	}
	return hotspot.Hotspot{}, shared.ErrNotFound
}

func matches(item hotspot.Hotspot, filter hotspot.ListFilter) bool {
	if filter.Status != nil && item.Status != *filter.Status {
		return false
	}
	if strings.TrimSpace(filter.RuleKey) != "" && item.RuleKey != strings.TrimSpace(filter.RuleKey) {
		return false
	}
	if filter.Severity != nil && item.Severity != *filter.Severity {
		return false
	}
	query := strings.ToLower(strings.TrimSpace(filter.Search))
	if query != "" && !strings.Contains(strings.ToLower(strings.Join([]string{item.Key, item.RuleKey, item.Title, item.Description, item.Location}, "\x00")), query) {
		return false
	}
	return true
}

func afterCursor(items []hotspot.Hotspot, beforeAt time.Time, beforeID shared.ID) []hotspot.Hotspot {
	for i, item := range items {
		if item.LastSeenAt.Before(beforeAt) || (item.LastSeenAt.Equal(beforeAt) && item.ID < beforeID) {
			return items[i:]
		}
	}
	return nil
}

func facets(items []hotspot.Hotspot) hotspot.Facets {
	out := hotspot.Facets{Statuses: map[string]int{}, RuleKeys: map[string]int{}, Severities: map[string]int{}}
	for _, item := range items {
		out.Statuses[string(item.Status)]++
		out.RuleKeys[item.RuleKey]++
		out.Severities[string(item.Severity)]++
	}
	return out
}

func cloneHotspot(in hotspot.Hotspot) hotspot.Hotspot {
	out := in
	return out
}
