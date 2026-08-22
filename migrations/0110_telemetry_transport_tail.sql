-- +goose Up
-- A3 (#624) tail: materialize two server-authoritative transport facts that cannot
-- safely live only in agent memory: the enrolled-agent -> canonical host-asset binding,
-- and the current/history view of sequence gaps. telemetry_stream_positions remains
-- the ACK source of truth; telemetry_transport_gaps is reconciled transactionally from
-- that snapshot so a filled hole is resolved rather than left as a phantom.

-- fleet_agents.id is globally unique, but PostgreSQL requires a UNIQUE target whose
-- columns exactly match a composite FK. Materialize the tenant-scoped identity pair so
-- telemetry_asset_bindings can enforce that its tenant_id and agent_id belong together
-- rather than combining an agent from one tenant with an independently valid tenant id.
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
-- request body. Keep the telemetry binding synchronized in the same asset transaction,
-- so ingest cannot race a successful host reconciliation and trust an agent-chosen asset.
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

    -- A host has one active reporting fleet identity. Re-enrolment/replacement moves
    -- ownership to the newly authenticated agent instead of leaving a stale sibling binding.
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
DROP TRIGGER fleet_assets_sync_telemetry_binding ON fleet_assets;
DROP FUNCTION synapse_sync_telemetry_asset_binding();
DROP TABLE telemetry_asset_bindings;
ALTER TABLE fleet_agents DROP CONSTRAINT uq_fleet_agents_tenant_id;
