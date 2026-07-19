package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/hotspot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.ProjectAnalysisProjectionStore = (*ProjectAnalysisStore)(nil)
var _ ports.ProjectHotspotStore = (*ProjectAnalysisStore)(nil)

// SaveWithResultAndHotspots commits the immutable analysis and its projection in
// one PostgreSQL transaction. A projection write failure rolls the analysis back,
// so the scan worker cannot publish a successful analysis without its hotspots.
func (r *ProjectAnalysisStore) SaveWithResultAndHotspots(ctx context.Context, analysis projectanalysis.Analysis, result []byte, candidates []hotspot.Candidate) error {
	items := make([]hotspot.Hotspot, len(candidates))
	for i, candidate := range candidates {
		item, err := projectedHotspot(analysis, candidate)
		if err != nil {
			return err
		}
		items[i] = item
	}
	payload, err := json.Marshal(analysis)
	if err != nil {
		return fmt.Errorf("marshal project analysis: %w", err)
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin project analysis transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO project_analyses (id, tenant_id, project_id, created_at, payload, result)
		VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (id) DO NOTHING`,
		analysis.ID, analysis.TenantID, analysis.ProjectID, analysis.CreatedAt, payload, result); err != nil {
		return fmt.Errorf("insert project analysis: %w", err)
	}
	for _, item := range items {
		if _, err := tx.Exec(ctx, `INSERT INTO project_hotspots
			(id, tenant_id, project_id, hotspot_key, finding_identity, rule_key, title, description, severity, finding_kind, cwe, location,
			 status, version, first_seen_analysis_id, last_seen_analysis_id, first_seen_at, last_seen_at, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$17,$18)
			ON CONFLICT (tenant_id, project_id, hotspot_key) DO UPDATE SET
				finding_identity = EXCLUDED.finding_identity,
				first_seen_analysis_id = CASE WHEN (EXCLUDED.first_seen_at, EXCLUDED.first_seen_analysis_id) < (project_hotspots.first_seen_at, project_hotspots.first_seen_analysis_id) THEN EXCLUDED.first_seen_analysis_id ELSE project_hotspots.first_seen_analysis_id END,
				first_seen_at = CASE WHEN (EXCLUDED.first_seen_at, EXCLUDED.first_seen_analysis_id) < (project_hotspots.first_seen_at, project_hotspots.first_seen_analysis_id) THEN EXCLUDED.first_seen_at ELSE project_hotspots.first_seen_at END,
				created_at = CASE WHEN (EXCLUDED.first_seen_at, EXCLUDED.first_seen_analysis_id) < (project_hotspots.first_seen_at, project_hotspots.first_seen_analysis_id) THEN EXCLUDED.created_at ELSE project_hotspots.created_at END,
				rule_key = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) THEN EXCLUDED.rule_key ELSE project_hotspots.rule_key END,
				title = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) THEN EXCLUDED.title ELSE project_hotspots.title END,
				description = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) THEN EXCLUDED.description ELSE project_hotspots.description END,
				severity = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) THEN EXCLUDED.severity ELSE project_hotspots.severity END,
				finding_kind = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) THEN EXCLUDED.finding_kind ELSE project_hotspots.finding_kind END,
				cwe = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) THEN EXCLUDED.cwe ELSE project_hotspots.cwe END,
				location = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) THEN EXCLUDED.location ELSE project_hotspots.location END,
				last_seen_analysis_id = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) THEN EXCLUDED.last_seen_analysis_id ELSE project_hotspots.last_seen_analysis_id END,
				last_seen_at = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) THEN EXCLUDED.last_seen_at ELSE project_hotspots.last_seen_at END,
				updated_at = CASE WHEN (EXCLUDED.last_seen_at, EXCLUDED.last_seen_analysis_id) > (project_hotspots.last_seen_at, project_hotspots.last_seen_analysis_id) THEN EXCLUDED.updated_at ELSE project_hotspots.updated_at END`,
			item.ID, item.TenantID, item.ProjectID, item.Key, item.FindingIdentity, item.RuleKey, item.Title, item.Description,
			item.Severity, item.Kind, item.CWE, item.Location, item.Status, item.Version, item.FirstSeenAnalysisID,
			item.LastSeenAnalysisID, item.FirstSeenAt, item.LastSeenAt); err != nil {
			return fmt.Errorf("upsert project hotspot: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit project analysis transaction: %w", err)
	}
	return nil
}

func projectedHotspot(analysis projectanalysis.Analysis, candidate hotspot.Candidate) (hotspot.Hotspot, error) {
	item := hotspot.Hotspot{
		ID:       hotspot.DeterministicID(shared.ID(analysis.TenantID), shared.ID(analysis.ProjectID), candidate.Key),
		TenantID: shared.ID(analysis.TenantID), ProjectID: shared.ID(analysis.ProjectID), Key: candidate.Key,
		FindingIdentity: candidate.FindingIdentity, RuleKey: candidate.RuleKey, Title: candidate.Title,
		Description: candidate.Description, Severity: candidate.Severity, Kind: candidate.Kind, CWE: candidate.CWE,
		Location: candidate.Location, Status: hotspot.StatusToReview, Version: 1,
		FirstSeenAnalysisID: analysis.ID, LastSeenAnalysisID: analysis.ID,
		FirstSeenAt: analysis.CreatedAt, LastSeenAt: analysis.CreatedAt,
		Audit: shared.Audit{CreatedAt: analysis.CreatedAt, UpdatedAt: analysis.CreatedAt},
	}
	if err := item.Validate(); err != nil {
		return hotspot.Hotspot{}, err
	}
	return item, nil
}

func (r *ProjectAnalysisStore) ListHotspots(ctx context.Context, tenantID, projectID shared.ID, filter hotspot.ListFilter) (hotspot.Page, error) {
	where, args := hotspotWhere(tenantID, projectID, filter, true)
	limit := filter.Limit
	if limit <= 0 {
		limit = 25
	}
	args = append(args, limit+1)
	query := `SELECT id, tenant_id, project_id, hotspot_key, finding_identity, rule_key, title, description, severity, finding_kind, cwe, location,
		status, version, first_seen_analysis_id, last_seen_analysis_id, first_seen_at, last_seen_at, created_at, updated_at
		FROM project_hotspots WHERE ` + where + ` ORDER BY last_seen_at DESC, id COLLATE "C" DESC LIMIT $` + fmt.Sprint(len(args))
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
	facetWhere, facetArgs := hotspotWhere(tenantID, projectID, filter, false)
	facetRows, err := r.pool.Query(ctx, `SELECT 'status', status, count(*) FROM project_hotspots WHERE `+facetWhere+` GROUP BY status
		UNION ALL SELECT 'rule', rule_key, count(*) FROM project_hotspots WHERE `+facetWhere+` GROUP BY rule_key
		UNION ALL SELECT 'severity', severity, count(*) FROM project_hotspots WHERE `+facetWhere+` GROUP BY severity`, facetArgs...)
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

func hotspotWhere(tenantID, projectID shared.ID, filter hotspot.ListFilter, cursor bool) (string, []any) {
	args := []any{tenantID.String(), projectID.String()}
	parts := []string{"tenant_id = $1", "project_id = $2"}
	add := func(part string, value any) {
		args = append(args, value)
		parts = append(parts, fmt.Sprintf(part, len(args)))
	}
	if filter.Status != nil {
		add("status = $%d", string(*filter.Status))
	}
	if strings.TrimSpace(filter.RuleKey) != "" {
		add("rule_key = $%d", strings.TrimSpace(filter.RuleKey))
	}
	if filter.Severity != nil {
		add("severity = $%d", string(*filter.Severity))
	}
	if search := strings.TrimSpace(filter.Search); search != "" {
		searchArg := len(args) + 1
		args = append(args, "%"+search+"%", "%"+search+"%", "%"+search+"%", "%"+search+"%", "%"+search+"%")
		parts = append(parts, fmt.Sprintf("(hotspot_key ILIKE $%d OR rule_key ILIKE $%d OR title ILIKE $%d OR description ILIKE $%d OR location ILIKE $%d)", searchArg, searchArg+1, searchArg+2, searchArg+3, searchArg+4))
	}
	if cursor && !filter.BeforeLastSeenAt.IsZero() {
		args = append(args, filter.BeforeLastSeenAt, filter.BeforeID.String())
		at, id := len(args)-1, len(args)
		parts = append(parts, fmt.Sprintf(`(last_seen_at < $%d OR (last_seen_at = $%d AND id COLLATE "C" < $%d))`, at, at, id))
	}
	return strings.Join(parts, " AND "), args
}

func (r *ProjectAnalysisStore) GetHotspot(ctx context.Context, tenantID, projectID, hotspotID shared.ID) (hotspot.Hotspot, error) {
	row := r.pool.QueryRow(ctx, `SELECT id, tenant_id, project_id, hotspot_key, finding_identity, rule_key, title, description, severity, finding_kind, cwe, location,
		status, version, first_seen_analysis_id, last_seen_analysis_id, first_seen_at, last_seen_at, created_at, updated_at
		FROM project_hotspots WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, tenantID.String(), projectID.String(), hotspotID.String())
	item, err := scanHotspot(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return hotspot.Hotspot{}, shared.ErrNotFound
	}
	if err != nil {
		return hotspot.Hotspot{}, fmt.Errorf("get project hotspot: %w", err)
	}
	return item, nil
}

func scanHotspot(row rowScanner) (hotspot.Hotspot, error) {
	var item hotspot.Hotspot
	var tenantID, projectID, status, kind, severity string
	var createdAt, updatedAt time.Time
	if err := row.Scan(&item.ID, &tenantID, &projectID, &item.Key, &item.FindingIdentity, &item.RuleKey, &item.Title, &item.Description,
		&severity, &kind, &item.CWE, &item.Location, &status, &item.Version, &item.FirstSeenAnalysisID, &item.LastSeenAnalysisID,
		&item.FirstSeenAt, &item.LastSeenAt, &createdAt, &updatedAt); err != nil {
		return hotspot.Hotspot{}, err
	}
	item.TenantID, item.ProjectID = shared.ID(tenantID), shared.ID(projectID)
	item.Severity, item.Kind, item.Status = shared.Severity(severity), finding.Kind(kind), hotspot.Status(status)
	item.Audit = shared.Audit{CreatedAt: createdAt, UpdatedAt: updatedAt}
	return item, nil
}
