-- +goose Up
-- Phase 4 (E19.1): the durable HITL approval queue. A proposed agent action is enqueued
-- 'pending'; a human Decides it (approved|denied) or a background sweep flips an undecided
-- action to 'timeout' (fail-closed). Decide is idempotent at the use-case layer (the first
-- decision wins) so a double-click/race can't re-open an admitted action.
CREATE TABLE agent_approvals (
    action_id       TEXT PRIMARY KEY,
    tenant_id       TEXT,
    session_id      TEXT NOT NULL,
    engagement_id   TEXT NOT NULL REFERENCES engagements(id),
    tool            TEXT NOT NULL,
    action          TEXT NOT NULL,             -- audit verb, e.g. recon.naabu
    target_kind     TEXT NOT NULL DEFAULT '',
    target_value    TEXT NOT NULL DEFAULT '',
    argv            JSONB,                      -- diff-before-run: exact command
    egress_preview  JSONB,                      -- in-scope destinations the run would reach
    risk            TEXT NOT NULL,              -- read|active|intrusive
    rationale       TEXT NOT NULL DEFAULT '',
    proposed_at     TIMESTAMPTZ NOT NULL,
    decision_state  TEXT NOT NULL DEFAULT 'pending', -- pending|approved|denied|timeout
    decided_by      TEXT NOT NULL DEFAULT '',        -- human actor (empty on timeout)
    decision_reason TEXT NOT NULL DEFAULT '',
    decided_at      TIMESTAMPTZ
);
-- Fast lookup of the per-engagement pending queue (the approval UI).
CREATE INDEX idx_agent_approvals_pending ON agent_approvals(engagement_id) WHERE decision_state = 'pending';

-- +goose Down
DROP TABLE agent_approvals;
