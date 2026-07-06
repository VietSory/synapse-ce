-- +goose Up
-- E5 recon: a recon run is one argv-based tool execution against an in-scope
-- target. Generalizes the Phase-1 scan_jobs idea for reconnaissance (the bare
-- goroutine is replaced by a real bounded worker pool). evidence_id links to the
-- sealed terminal_log in the hash-chained evidence ledger (golden rule 5).
CREATE TABLE recon_runs (
    id            TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    tool          TEXT NOT NULL,
    target        TEXT NOT NULL,
    status        TEXT NOT NULL,                -- queued | running | succeeded | failed
    stage         TEXT NOT NULL DEFAULT '',
    error         TEXT NOT NULL DEFAULT '',
    result_count  INT  NOT NULL DEFAULT 0,
    evidence_id   TEXT NOT NULL DEFAULT '',
    started_at    TIMESTAMPTZ NOT NULL,
    finished_at   TIMESTAMPTZ
);
CREATE INDEX idx_recon_runs_engagement ON recon_runs (engagement_id, started_at DESC);

-- +goose Down
DROP TABLE IF EXISTS recon_runs;
