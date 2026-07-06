-- +goose Up
-- Phase 3 (E14.4): record the per-run containment posture (sandboxed-live / egress-
-- restricted / isolated / unsandboxed) so the recon UI can show, per run, how the tool
-- was confined. Sourced from the sealed containment_profile evidence (E9.5); this is the
-- operator-facing summary. Empty for pre-existing runs.
ALTER TABLE recon_runs ADD COLUMN containment TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE recon_runs DROP COLUMN containment;
