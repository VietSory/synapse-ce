-- +goose Up
-- A3 tail: persist agent-origin spool loss separately from delivery-sequence holes.
-- Local quota/corruption/recovery loss may not have a trustworthy sequence coordinate,
-- and must never be auto-resolved by a later delivery gap fill.
CREATE TABLE telemetry_agent_gaps (
    tenant_id         TEXT NOT NULL REFERENCES tenants(id),
    gap_id            TEXT NOT NULL,
    host_id           TEXT NOT NULL,
    asset_id          TEXT NOT NULL,
    agent_id          TEXT NOT NULL,
    agent_session_id  TEXT NOT NULL,
    stream_id         TEXT NOT NULL,
    priority          SMALLINT NOT NULL CHECK (priority BETWEEN 0 AND 3),
    epoch             BIGINT NOT NULL CHECK (epoch > 0),
    known_sequence    BOOLEAN NOT NULL,
    from_sequence     BIGINT,
    to_sequence       BIGINT,
    reason            TEXT NOT NULL,
    count             BIGINT NOT NULL CHECK (count > 0),
    occurred_at       TIMESTAMPTZ NOT NULL,
    received_at       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, agent_id, gap_id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES fleet_agents(tenant_id, id),
    FOREIGN KEY (tenant_id, asset_id) REFERENCES fleet_assets(tenant_id, id),
    CHECK (
        (known_sequence
            AND from_sequence IS NOT NULL AND from_sequence > 0
            AND to_sequence IS NOT NULL AND to_sequence >= from_sequence
            AND count = to_sequence - from_sequence + 1)
        OR
        (NOT known_sequence AND from_sequence IS NULL AND to_sequence IS NULL)
    )
);
CREATE INDEX idx_telemetry_agent_gaps_hunt
    ON telemetry_agent_gaps (tenant_id, host_id, asset_id, occurred_at);
CREATE INDEX idx_telemetry_agent_gaps_stream
    ON telemetry_agent_gaps (tenant_id, stream_id, epoch, priority, occurred_at);
CALL synapse_enable_tenant_rls('telemetry_agent_gaps');

-- +goose Down
-- Refuse destructive rollback once agent-origin loss evidence has been accepted.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM telemetry_agent_gaps) THEN
        RAISE EXCEPTION 'cannot roll back 0110: telemetry agent gap provenance exists';
    END IF;
END $$;
-- +goose StatementEnd
DROP TABLE telemetry_agent_gaps;
