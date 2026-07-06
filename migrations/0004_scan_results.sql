-- +goose Up
-- Cache the latest full scan result (JSON) per engagement so the UI can rehydrate
-- the SBOM / vulnerabilities / dependency graph / languages / provenance after a
-- page reload (the normalized scan tables are write-only and omit those).
CREATE TABLE scan_results (
    engagement_id TEXT PRIMARY KEY,
    result        JSONB NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS scan_results;
