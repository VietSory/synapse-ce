-- +goose Up
-- Detection provenance on findings (Phase 1.6): which sources detected the
-- underlying vuln + the multi-source confidence, so reports + the UI can show
-- "Detected by" and "Confidence". Backward compatible (defaults).
ALTER TABLE findings ADD COLUMN sources    TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN confidence TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE findings DROP COLUMN confidence;
ALTER TABLE findings DROP COLUMN sources;
