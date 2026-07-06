-- +goose Up
-- Phase 4 hardening PR0/PR1. jobs_run_lock is a ROW-LEASE run lock (LeaseRunLock): unlike the
-- advisory pg_try_advisory_lock it does NOT pin a pooled connection for the whole run, so many
-- concurrent recon runs no longer starve the connection pool. A lease is acquired by upserting
-- the row if it is free or its claim has expired, renewed by a background tick, and released by
-- deleting the owner's row. (The agent SESSION lock keeps the connection-holding advisory lock
-- so it cannot expire mid-LLM-loop and let a second worker double-run an admitted action.)
CREATE TABLE jobs_run_lock (
    run_id        TEXT PRIMARY KEY,
    owner         TEXT NOT NULL,            -- per-process id; release/renew are owner-scoped
    claimed_until TIMESTAMPTZ NOT NULL,     -- lease expiry; a claim past this is stealable
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_jobs_run_lock_claimed_until ON jobs_run_lock(claimed_until);

-- Startup reconciliation (PR1) lists sessions stranded by a crash; the partial index keeps that
-- scan cheap and ignores the terminal majority.
CREATE INDEX idx_agent_sessions_resumable ON agent_sessions(updated_at)
    WHERE status IN ('running', 'awaiting_approval');

-- +goose Down
DROP INDEX idx_agent_sessions_resumable;
DROP TABLE jobs_run_lock;
