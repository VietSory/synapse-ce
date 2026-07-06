-- +goose Up
-- Risk-priority columns on findings (CISA KEV -> EPSS x CVSS); FR-A6 ordering.
ALTER TABLE findings ADD COLUMN kev BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE findings ADD COLUMN risk_score DOUBLE PRECISION NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE findings DROP COLUMN risk_score;
ALTER TABLE findings DROP COLUMN kev;
