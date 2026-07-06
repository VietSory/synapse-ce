-- +goose Up
-- Phase 4 (E19.3 carry-forward): record WHO proposed an AI/exploitation finding so the
-- adversarial verifier that later raises its evidence score cannot be the same actor (golden
-- rule 5: a finding cannot confirm itself). Empty for SCA/recon/manual findings.
ALTER TABLE findings ADD COLUMN proposed_by TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE findings DROP COLUMN proposed_by;
