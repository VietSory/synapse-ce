-- +goose Up
-- Asynchronous scan-job status so the UI can show progress and survive a reload.
CREATE TABLE scan_jobs (
    id            TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    target        TEXT NOT NULL,
    kind          TEXT NOT NULL,
    status        TEXT NOT NULL,                -- running | succeeded | failed
    stage         TEXT NOT NULL,
    progress      INT  NOT NULL DEFAULT 0,
    error         TEXT,
    started_at    TIMESTAMPTZ NOT NULL,
    finished_at   TIMESTAMPTZ
);
CREATE INDEX idx_scan_jobs_engagement ON scan_jobs (engagement_id, started_at DESC);

-- +goose Down
DROP TABLE IF EXISTS scan_jobs;
