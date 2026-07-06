-- +goose Up
-- Phase 4 hardening PR4 (ADR-0013): the STRUCTURED agent decision log. One row per orchestrator
-- step (executed/denied/read/error) + one terminal stop row, so a run is explainable from stored
-- data (why-tool / why-target / why-stopped) without parsing the untrusted LLM transcript. It is
-- a queryable projection ALONGSIDE the authoritative evidence chain: `refs` holds chain link
-- HASHES only (no content, no secrets); `reason` holds the redacted rationale + observation
-- summary. seq is a monotonic per-session counter. The partial unique indexes make AppendDecision
-- idempotent (one row per action for steps; one stop per session), so a redelivered drive cannot
-- fork the log.
CREATE TABLE agent_decisions (
    session_id    TEXT NOT NULL REFERENCES agent_sessions(id) ON DELETE CASCADE,
    seq           INT  NOT NULL,
    engagement_id TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('step','stop')),
    outcome       TEXT NOT NULL DEFAULT '',
    action_id     TEXT NOT NULL DEFAULT '',
    tool          TEXT NOT NULL DEFAULT '',
    action        TEXT NOT NULL DEFAULT '',
    target        TEXT NOT NULL DEFAULT '',
    risk          TEXT NOT NULL DEFAULT '',
    decided_by    TEXT NOT NULL DEFAULT '',
    stop_reason   TEXT NOT NULL DEFAULT '',
    reason        JSONB NOT NULL DEFAULT '{}',
    refs          JSONB NOT NULL DEFAULT '{}',
    created_by    TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (session_id, seq)
);
CREATE INDEX idx_agent_decisions_engagement ON agent_decisions(engagement_id, created_at);
-- Idempotency: one step decision per action, one stop per session.
CREATE UNIQUE INDEX idx_agent_decisions_step_action ON agent_decisions(session_id, action_id) WHERE kind = 'step' AND action_id <> '';
CREATE UNIQUE INDEX idx_agent_decisions_one_stop ON agent_decisions(session_id) WHERE kind = 'stop';

-- +goose Down
DROP TABLE agent_decisions;
