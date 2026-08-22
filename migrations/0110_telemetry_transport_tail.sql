-- +goose Up
-- A3 (#624) tail: materialize server-authoritative transport facts that cannot
-- safely live only in agent memory: the enrolled-agent -> canonical host-asset binding,
-- the exact batch commitment occupying each delivery sequence, and the current/history
-- view of sequence gaps. telemetry_stream_positions remains the ACK source of truth.

ALTER TABLE fleet_agents
    ADD CONSTRAINT uq_fleet_agents_tenant_id UNIQUE (tenant_id, id);

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

-- Host inventory stamps reporting_agent_id from the authenticated actor, never the
-- request body. Keep the telemetry binding synchronized in the same asset transaction.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION synapse_sync_telemetry_asset_binding()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    reporting_agent TEXT;
BEGIN
    IF NEW.kind <> 'host' THEN
        RETURN NEW;
    END IF;
    reporting_agent := NULLIF(btrim(NEW.attributes ->> 'reporting_agent_id'), '');
    IF reporting_agent IS NULL THEN
        RETURN NEW;
    END IF;

    DELETE FROM telemetry_asset_bindings
      WHERE tenant_id = NEW.tenant_id
        AND asset_id = NEW.id
        AND agent_id <> reporting_agent;

    INSERT INTO telemetry_asset_bindings (tenant_id, agent_id, asset_id, updated_at)
    VALUES (NEW.tenant_id, reporting_agent, NEW.id, NEW.updated_at)
    ON CONFLICT (tenant_id, agent_id) DO UPDATE
      SET asset_id = EXCLUDED.asset_id,
          updated_at = EXCLUDED.updated_at
      WHERE telemetry_asset_bindings.updated_at <= EXCLUDED.updated_at;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER fleet_assets_sync_telemetry_binding
AFTER INSERT OR UPDATE OF attributes, updated_at ON fleet_assets
FOR EACH ROW EXECUTE FUNCTION synapse_sync_telemetry_asset_binding();

-- One immutable signed-batch identity per delivery coordinate. The observed-time
-- span and priority are derived from the already-verified canonical events and let
-- missing neighboring sequences be materialized as coverage windows, not point markers.
CREATE TABLE telemetry_batch_commits (
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    agent_id        TEXT NOT NULL,
    stream_id       TEXT NOT NULL,
    epoch           BIGINT NOT NULL CHECK (epoch >= 1),
    sequence        BIGINT NOT NULL CHECK (sequence >= 1),
    batch_id        TEXT NOT NULL,
    asset_id        TEXT NOT NULL,
    priority        INT NOT NULL CHECK (priority BETWEEN 0 AND 3),
    schema_version  INT NOT NULL CHECK (schema_version >= 1),
    payload_digest  TEXT NOT NULL,
    event_count     INT NOT NULL CHECK (event_count >= 1),
    event_time_min  TIMESTAMPTZ NOT NULL,
    event_time_max  TIMESTAMPTZ NOT NULL CHECK (event_time_max >= event_time_min),
    committed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, agent_id, stream_id, epoch, sequence)
);
CREATE INDEX idx_telemetry_batch_commits_batch
    ON telemetry_batch_commits (tenant_id, batch_id);
CALL synapse_enable_tenant_rls('telemetry_batch_commits');

CREATE TABLE telemetry_transport_gaps (
    tenant_id      TEXT NOT NULL REFERENCES tenants(id),
    agent_id       TEXT NOT NULL,
    -- Coverage metadata is nullable for low-level ACK-state repair/import paths that
    -- do not yet have the neighboring batch commitments. The live ingest path always
    -- commits the received batch first, so production gaps are enriched immediately.
    asset_id       TEXT,
    stream_id      TEXT NOT NULL,
    priority       INT CHECK (priority BETWEEN 0 AND 3),
    epoch          BIGINT NOT NULL CHECK (epoch >= 1),
    from_sequence  BIGINT NOT NULL CHECK (from_sequence >= 1),
    to_sequence    BIGINT NOT NULL CHECK (to_sequence >= from_sequence),
    from_at        TIMESTAMPTZ,
    to_at          TIMESTAMPTZ,
    detected_at    TIMESTAMPTZ NOT NULL,
    resolved_at    TIMESTAMPTZ,
    CONSTRAINT telemetry_transport_gaps_time_pair CHECK (
        (from_at IS NULL AND to_at IS NULL) OR
        (from_at IS NOT NULL AND to_at IS NOT NULL AND to_at >= from_at)
    ),
    CONSTRAINT telemetry_transport_gaps_coverage_pair CHECK (
        (asset_id IS NULL AND priority IS NULL AND from_at IS NULL AND to_at IS NULL) OR
        (asset_id IS NOT NULL AND priority IS NOT NULL AND from_at IS NOT NULL AND to_at IS NOT NULL)
    ),
    PRIMARY KEY (tenant_id, agent_id, stream_id, epoch, from_sequence, to_sequence, detected_at)
);
CREATE INDEX idx_telemetry_transport_gaps_open
    ON telemetry_transport_gaps (tenant_id, agent_id, stream_id, epoch, from_sequence)
    WHERE resolved_at IS NULL;
CREATE INDEX idx_telemetry_transport_gaps_coverage
    ON telemetry_transport_gaps (tenant_id, asset_id, priority, from_at, to_at)
    WHERE resolved_at IS NULL AND asset_id IS NOT NULL;
CREATE UNIQUE INDEX uq_telemetry_transport_gaps_open_range
    ON telemetry_transport_gaps (tenant_id, agent_id, stream_id, epoch, from_sequence, to_sequence)
    WHERE resolved_at IS NULL;
CALL synapse_enable_tenant_rls('telemetry_transport_gaps');

-- +goose Down
-- Gap rows are provenance. Refuse a destructive rollback once the live transport has
-- materialized any; operators must explicitly preserve/migrate that evidence first.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM telemetry_transport_gaps) THEN
        RAISE EXCEPTION 'cannot roll back 0110: telemetry transport gap provenance exists';
    END IF;
END $$;
-- +goose StatementEnd
DROP TABLE telemetry_transport_gaps;
DROP TABLE telemetry_batch_commits;
DROP TRIGGER fleet_assets_sync_telemetry_binding ON fleet_assets;
DROP FUNCTION synapse_sync_telemetry_asset_binding();
DROP TABLE telemetry_asset_bindings;
ALTER TABLE fleet_agents DROP CONSTRAINT uq_fleet_agents_tenant_id;
