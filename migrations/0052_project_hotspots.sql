-- +goose Up
CREATE TABLE project_hotspots (
    id                    TEXT PRIMARY KEY,
    tenant_id             TEXT NOT NULL REFERENCES tenants(id),
    project_id            TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    hotspot_key           TEXT NOT NULL,
    finding_identity      TEXT NOT NULL,
    rule_key              TEXT NOT NULL,
    title                 TEXT NOT NULL,
    description           TEXT NOT NULL,
    severity              TEXT NOT NULL,
    finding_kind          TEXT NOT NULL,
    cwe                   TEXT NOT NULL DEFAULT '',
    location              TEXT NOT NULL DEFAULT '',
    status                TEXT NOT NULL CHECK (status IN ('to_review', 'acknowledged', 'fixed', 'safe')),
    version               INTEGER NOT NULL CHECK (version >= 1),
    first_seen_analysis_id TEXT NOT NULL,
    last_seen_analysis_id  TEXT NOT NULL,
    first_seen_at          TIMESTAMPTZ NOT NULL,
    last_seen_at           TIMESTAMPTZ NOT NULL,
    last_reviewed_by       TEXT NOT NULL DEFAULT '',
    last_reviewed_at       TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL,
    updated_at             TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, project_id, hotspot_key)
);

CREATE INDEX idx_project_hotspots_tenant_project_status
    ON project_hotspots (tenant_id, project_id, status);
CREATE INDEX idx_project_hotspots_tenant_project_rule
    ON project_hotspots (tenant_id, project_id, rule_key);
CREATE INDEX idx_project_hotspots_tenant_project_seen
    ON project_hotspots (tenant_id, project_id, last_seen_at DESC, id COLLATE "C" DESC);

-- +goose Down
DROP TABLE project_hotspots;
