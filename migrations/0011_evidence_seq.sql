-- +goose Up
-- Monotonic sequence so the evidence chain is ordered by insertion, not by the
-- random UUID id (two links in the same instant must keep chain order). Phase E
-- hardening (go-arch review).
ALTER TABLE evidence ADD COLUMN seq BIGSERIAL;

-- +goose Down
ALTER TABLE evidence DROP COLUMN seq;
