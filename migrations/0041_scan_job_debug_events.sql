-- +goose Up
ALTER TABLE scan_jobs ADD COLUMN debug_events JSONB NOT NULL DEFAULT '[]'::jsonb;

-- +goose Down
ALTER TABLE scan_jobs DROP COLUMN IF EXISTS debug_events;
