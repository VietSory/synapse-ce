-- +goose Up
-- Reproducibility (Phase B): a per-execution manifest (tool/DB/source/correlation
-- versions + SBOM hash + repro score) plus the finding identity keys, so scan
-- history is listable and drift between two runs is explainable.
CREATE TABLE scan_runs (
    id            TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    manifest      JSONB NOT NULL,
    finding_keys  JSONB NOT NULL
);
CREATE INDEX idx_scan_runs_engagement ON scan_runs (engagement_id, created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS scan_runs;
