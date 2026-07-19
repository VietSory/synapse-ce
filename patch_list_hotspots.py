import sys

with open('internal/infrastructure/persistence/postgres/project_hotspot_store.go', 'r') as f:
    content = f.read()

import re

# Find ListHotspots function
list_hotspots_start = content.find('func (r *ProjectAnalysisStore) ListHotspots')
list_hotspots_end = content.find('func hotspotWhere', list_hotspots_start)
where_start = list_hotspots_end
where_end = content.find('func (r *ProjectAnalysisStore) GetHotspot', where_start)

# We will replace ListHotspots and hotspotWhere entirely
new_funcs = '''func (r *ProjectAnalysisStore) ListHotspots(ctx context.Context, tenantID, projectID shared.ID, filter hotspot.ListFilter) (hotspot.Page, error) {
	where, args, joins := hotspotWhere(tenantID, projectID, filter, true)
	limit := filter.Limit
	if limit <= 0 {
		limit = 25
	}
	args = append(args, limit+1)
	query := `SELECT ph.id, ph.tenant_id, ph.project_id, ph.hotspot_key, ph.finding_identity, ph.rule_key, ph.title, ph.description, ph.severity, ph.finding_kind, ph.cwe, ph.location,
		ph.status, ph.version, ph.first_seen_analysis_id, ph.last_seen_analysis_id, ph.first_seen_at, ph.last_seen_at, ph.created_at, ph.updated_at, ph.last_reviewed_by, ph.last_reviewed_at
		FROM project_hotspots ph ` + joins + ` WHERE ` + where + ` ORDER BY ph.last_seen_at DESC, ph.id COLLATE "C" DESC LIMIT $` + fmt.Sprint(len(args))
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return hotspot.Page{}, fmt.Errorf("list project hotspots: %w", err)
	}
	defer rows.Close()
	items := make([]hotspot.Hotspot, 0, limit+1)
	for rows.Next() {
		item, err := scanHotspot(rows)
		if err != nil {
			return hotspot.Page{}, fmt.Errorf("scan project hotspot: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return hotspot.Page{}, err
	}
	page := hotspot.Page{}
	if len(items) > limit {
		last := items[limit-1]
		page.Next = &hotspot.Cursor{BeforeLastSeenAt: last.LastSeenAt, BeforeID: last.ID}
		items = items[:limit]
	}
	page.Items = items
	
	facetWhere, facetArgs, facetJoins := hotspotWhere(tenantID, projectID, filter, false)
	
	// Query Summary
	var total, reviewed int
	err = r.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE ph.status IN ('acknowledged', 'fixed', 'safe')) FROM project_hotspots ph ` + facetJoins + ` WHERE ` + facetWhere, facetArgs...).Scan(&total, &reviewed)
	if err != nil {
		return hotspot.Page{}, fmt.Errorf("summary project hotspots: %w", err)
	}
	
	page.Summary = hotspot.CalculateSummary(total, reviewed)

	facetRows, err := r.pool.Query(ctx, `SELECT 'status' as kind, ph.status as value, count(*) FROM project_hotspots ph `+facetJoins+` WHERE `+facetWhere+` GROUP BY ph.status
		UNION ALL SELECT 'rule', ph.rule_key, count(*) FROM project_hotspots ph `+facetJoins+` WHERE `+facetWhere+` GROUP BY ph.rule_key
		UNION ALL SELECT 'severity', ph.severity, count(*) FROM project_hotspots ph `+facetJoins+` WHERE `+facetWhere+` GROUP BY ph.severity`, facetArgs...)
	if err != nil {
		return hotspot.Page{}, fmt.Errorf("facet project hotspots: %w", err)
	}
	defer facetRows.Close()
	page.Facets = hotspot.Facets{Statuses: map[string]int{}, RuleKeys: map[string]int{}, Severities: map[string]int{}}
	for facetRows.Next() {
		var kind, value string
		var count int
		if err := facetRows.Scan(&kind, &value, &count); err != nil {
			return hotspot.Page{}, fmt.Errorf("scan project hotspot facet: %w", err)
		}
		switch kind {
		case "status":
			page.Facets.Statuses[value] = count
		case "rule":
			page.Facets.RuleKeys[value] = count
		case "severity":
			page.Facets.Severities[value] = count
		}
	}
	return page, facetRows.Err()
}

func hotspotWhere(tenantID, projectID shared.ID, filter hotspot.ListFilter, cursor bool) (string, []any, string) {
	args := []any{tenantID.String(), projectID.String()}
	parts := []string{"ph.tenant_id = $1", "ph.project_id = $2"}
	add := func(part string, value any) {
		args = append(args, value)
		parts = append(parts, fmt.Sprintf(part, len(args)))
	}
	if filter.Status != nil {
		add("ph.status = $%d", string(*filter.Status))
	}
	if strings.TrimSpace(filter.RuleKey) != "" {
		add("ph.rule_key = $%d", strings.TrimSpace(filter.RuleKey))
	}
	if filter.Severity != nil {
		add("ph.severity = $%d", string(*filter.Severity))
	}
	if search := strings.TrimSpace(filter.Search); search != "" {
		searchArg := len(args) + 1
		search = strings.ReplaceAll(search, "\\\\", "\\\\\\\\")
		search = strings.ReplaceAll(search, "%", "\\\\%")
		search = strings.ReplaceAll(search, "_", "\\\\_")
		
		args = append(args, "%"+search+"%", "%"+search+"%", "%"+search+"%", "%"+search+"%", "%"+search+"%")
		parts = append(parts, fmt.Sprintf("(ph.hotspot_key ILIKE $%d OR ph.rule_key ILIKE $%d OR ph.title ILIKE $%d OR ph.description ILIKE $%d OR ph.location ILIKE $%d)", searchArg, searchArg+1, searchArg+2, searchArg+3, searchArg+4))
	}
	
	joins := ""
	if filter.Lens == hotspot.LensNewCode {
		joins = ` JOIN project_analyses pa ON pa.project_id = ph.project_id AND pa.tenant_id = ph.tenant_id AND pa.is_latest = true
				  JOIN project_analysis_hotspots pah ON pah.analysis_id = pa.id AND pah.hotspot_id = ph.id AND pah.is_new = true `
	}

	if cursor && !filter.BeforeLastSeenAt.IsZero() {
		args = append(args, filter.BeforeLastSeenAt, filter.BeforeID.String())
		at, id := len(args)-1, len(args)
		parts = append(parts, fmt.Sprintf(`(ph.last_seen_at < $%d OR (ph.last_seen_at = $%d AND ph.id COLLATE "C" < $%d))`, at, at, id))
	}
	return strings.Join(parts, " AND "), args, joins
}
'''

new_content = content[:list_hotspots_start] + new_funcs + content[where_end:]

with open('internal/infrastructure/persistence/postgres/project_hotspot_store.go', 'w') as f:
    f.write(new_content)
