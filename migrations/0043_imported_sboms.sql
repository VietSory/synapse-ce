-- +goose Up
-- Active client-supplied CycloneDX SBOM per engagement. The raw JSON is kept as
-- the chain-of-custody input artifact; scan_results remains the UI cache.
CREATE TABLE imported_sboms (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL REFERENCES tenants(id),
    engagement_id    TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    filename         TEXT NOT NULL DEFAULT 'SBOM.json',
    format           TEXT NOT NULL DEFAULT 'cyclonedx',
    spec_version     TEXT NOT NULL,
    target_ref       TEXT NOT NULL,
    component_count  INT NOT NULL,
    dependency_count INT NOT NULL DEFAULT 0,
    sha256           TEXT NOT NULL,
    raw_json         JSONB NOT NULL,
    created_by       TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT imported_sboms_component_count_positive CHECK (component_count > 0),
    CONSTRAINT imported_sboms_dependency_count_nonnegative CHECK (dependency_count >= 0),
    CONSTRAINT imported_sboms_format_check CHECK (format = 'cyclonedx')
);

CREATE UNIQUE INDEX idx_imported_sboms_active ON imported_sboms(tenant_id, engagement_id);
CREATE INDEX idx_imported_sboms_tenant_created ON imported_sboms(tenant_id, created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS imported_sboms;
