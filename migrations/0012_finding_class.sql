-- +goose Up
-- Separate actionable third-party findings from first-party historical advisories
-- (Phase 1.9). Existing rows default to third_party (backward compatible).
ALTER TABLE findings ADD COLUMN class TEXT NOT NULL DEFAULT 'third_party';

-- +goose Down
ALTER TABLE findings DROP COLUMN class;
