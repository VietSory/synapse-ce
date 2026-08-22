-- +goose Up
-- A3 (#624) tail: materialize two server-authoritative transport facts that cannot
-- safely live only in agent memory: the enrolled-agent -> canonical host-asset binding,
-- and the current/history view of sequence gaps. telemetry_stream_positions remains
-- the ACK source of truth; telemetry_transport_gaps is reconciled transactionally from
-- that snapshot so a filled hole is resolved rather than left as a phantom.

CREATE TABLE telemetry_asset_bindings (
    tenant_id  TEXT NOT NULL REFERENCES tenants(id),
    agent_id   TEXT NOT NULL,
    asset_id   TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, agent_id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES fleet_agents(tenant_id, id),
    FOREIGN KEY (tenant_id, asset_id) REFERENCES fleet_assets(tenant_id, id)
);
CREATE INDEX idx_telemetry_asset_bindings_asset
    ON telemetry_asset_bindings (tenant_id, asset_id);
CALL synapse_enable_tenant_rls('telemetry_asset_bindings');

CREATE TABLE telemetry_transport_gaps (
    tenant_id      TEXT NOT NULL REFERENCES tenants(id),
    agent_id       TEXT NOT NULL,
    stream_id      TEXT NOT NULL,
    epoch          BIGINT NOT NULL CHECK (epoch >= 1),
    from_sequence  BIGINT NOT NULL CHECK (from_sequence >= 1),
    to_sequence    BIGINT NOT NULL CHECK (to_sequence >= from_sequence),
    detected_at    TIMESTAMPTZ NOT NULL,
    resolved_at    TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, agent_id, stream_id, epoch, from_sequence, to_sequence, detected_at)
);
CREATE INDEX idx_telemetry_transport_gaps_open
    ON telemetry_transport_gaps (tenant_id, agent_id, stream_id, epoch, from_sequence)
    WHERE resolved_at IS NULL;
CREATE UNIQUE INDEX uq_telemetry_transport_gaps_open_range
    ON telemetry_transport_gaps (tenant_id, agent_id, stream_id, epoch, from_sequence, to_sequence)
    WHERE resolved_at IS NULL;
CALL synapse_enable_tenant_rls('telemetry_transport_gaps');

-- +goose Down
-- Bindings are reconstructible from a new authenticated host inventory. Gap history is
-- transport provenance, but rollback is allowed before release just like migration 0109.
DROP TABLE telemetry_transport_gaps;
DROP TABLE telemetry_asset_bindings;
