-- +goose Up
-- A3 live telemetry transport (#624): persist schema + incarnation-aware delivery
-- coordinates without overloading the legacy per-(host,class) sequence key. A reboot
-- advances Epoch and may legitimately reset Sequence to 1, so A3 idempotency is keyed
-- by the explicit delivery_key while legacy rows retain their original uniqueness.

-- Composite FK target for tenant-safe references below. fleet_agents.id is globally
-- unique already; the composite constraint additionally proves the tenant relationship
-- to PostgreSQL (referential-integrity checks bypass RLS).
ALTER TABLE fleet_agents
    ADD CONSTRAINT fleet_agents_tenant_id_id_key UNIQUE (tenant_id, id);

ALTER TABLE telemetry_events
    ADD COLUMN row_id BIGSERIAL,
    ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1 CHECK (schema_version >= 1),
    ADD COLUMN agent_session_id TEXT,
    ADD COLUMN delivery_stream_id TEXT,
    ADD COLUMN delivery_priority SMALLINT,
    ADD COLUMN epoch BIGINT,
    ADD COLUMN batch_id TEXT,
    ADD COLUMN event_id TEXT,
    ADD COLUMN canonical_event JSONB,
    ADD COLUMN delivery_key TEXT,
    ADD COLUMN received_at TIMESTAMPTZ;

-- The legacy writer's ON CONFLICT target is exactly
-- (tenant_id,host_id,class,seq,idx). Preserve that shape as a unique index before
-- admitting nullable idx values for A3. PostgreSQL does not permit a primary-key
-- column to become nullable, so the old PK must be replaced first. The migration is
-- transactional, therefore no writer can observe a window without legacy uniqueness.
ALTER TABLE telemetry_events DROP CONSTRAINT telemetry_events_pkey;
ALTER TABLE telemetry_events ALTER COLUMN idx DROP NOT NULL;
ALTER TABLE telemetry_events ADD CONSTRAINT telemetry_events_pkey PRIMARY KEY (row_id);
CREATE UNIQUE INDEX telemetry_events_legacy_delivery_uq
    ON telemetry_events (tenant_id, host_id, class, seq, idx);

-- A3's stable idempotency key includes agent/session/delivery-stream/priority/epoch/
-- sequence/event-index. A resend is therefore a no-op while an Epoch reset is distinct.
CREATE UNIQUE INDEX telemetry_events_delivery_key_uq
    ON telemetry_events (tenant_id, delivery_key)
    WHERE delivery_key IS NOT NULL;

-- Replaces the useful leading-prefix lookup the old primary key provided. A3 rows
-- deliberately store seq=0/idx=NULL in this compatibility table; true transport
-- ordering lives in telemetry_delivery_sequences, so the old per-class gap detector
-- cannot invent gaps when one priority lane interleaves several event classes.
CREATE INDEX idx_telemetry_legacy_sequence
    ON telemetry_events (tenant_id, host_id, class, seq)
    WHERE delivery_key IS NULL;
CREATE INDEX idx_telemetry_delivery_window
    ON telemetry_events (tenant_id, delivery_stream_id, epoch, observed_at)
    WHERE delivery_key IS NOT NULL;
CREATE INDEX idx_telemetry_schema_version
    ON telemetry_events (tenant_id, schema_version, observed_at);

ALTER TABLE telemetry_events ADD CONSTRAINT telemetry_events_delivery_shape_check CHECK (
    (delivery_key IS NULL
        AND idx IS NOT NULL
        AND agent_session_id IS NULL
        AND delivery_stream_id IS NULL
        AND delivery_priority IS NULL
        AND epoch IS NULL
        AND batch_id IS NULL
        AND event_id IS NULL
        AND canonical_event IS NULL
        AND received_at IS NULL)
    OR
    (delivery_key IS NOT NULL
        AND seq = 0
        AND idx IS NULL
        AND agent_session_id IS NOT NULL
        AND delivery_stream_id IS NOT NULL
        AND delivery_priority BETWEEN 0 AND 3
        AND epoch > 0
        AND batch_id IS NOT NULL
        AND event_id IS NOT NULL
        AND canonical_event IS NOT NULL
        AND received_at IS NOT NULL)
);

-- One row serializes updates for one server-derived delivery lane. current_epoch is
-- monotonic: an older incarnation may be retried idempotently, but can never become
-- forward progress again after a reboot advanced this value.
CREATE TABLE telemetry_delivery_streams (
    tenant_id        TEXT NOT NULL REFERENCES tenants(id),
    agent_id         TEXT NOT NULL,
    agent_session_id TEXT NOT NULL,
    stream_id        TEXT NOT NULL,
    priority         SMALLINT NOT NULL CHECK (priority BETWEEN 0 AND 3),
    current_epoch    BIGINT NOT NULL CHECK (current_epoch > 0),
    updated_at       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, stream_id),
    UNIQUE (tenant_id, agent_id, agent_session_id, priority),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES fleet_agents(tenant_id, id)
);
CALL synapse_enable_tenant_rls('telemetry_delivery_streams');

-- Durable sequence ledger is the ACK authority. ACK is derived only from rows here;
-- receiving a request is never enough to acknowledge it.
CREATE TABLE telemetry_delivery_sequences (
    tenant_id        TEXT NOT NULL REFERENCES tenants(id),
    stream_id        TEXT NOT NULL,
    epoch            BIGINT NOT NULL CHECK (epoch > 0),
    sequence         BIGINT NOT NULL CHECK (sequence > 0),
    event_id         TEXT NOT NULL,
    event_digest     TEXT NOT NULL,
    delivery_key     TEXT NOT NULL,
    batch_id         TEXT NOT NULL,
    received_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, stream_id, epoch, sequence),
    UNIQUE (tenant_id, delivery_key),
    FOREIGN KEY (tenant_id, stream_id) REFERENCES telemetry_delivery_streams(tenant_id, stream_id) ON DELETE CASCADE
);
CREATE INDEX idx_telemetry_delivery_sequences_batch
    ON telemetry_delivery_sequences (tenant_id, batch_id);
CALL synapse_enable_tenant_rls('telemetry_delivery_sequences');

-- Batch provenance records the state transition Received -> TelemetryDurable ->
-- Acknowledged. The row is retained after ACK; it is provenance, not a queue item.
CREATE TABLE telemetry_delivery_batches (
    tenant_id          TEXT NOT NULL REFERENCES tenants(id),
    batch_id           TEXT NOT NULL,
    agent_id           TEXT NOT NULL,
    host_id            TEXT NOT NULL,
    asset_id           TEXT NOT NULL,
    agent_session_id   TEXT NOT NULL,
    stream_id          TEXT NOT NULL,
    priority           SMALLINT NOT NULL CHECK (priority BETWEEN 0 AND 3),
    epoch              BIGINT NOT NULL CHECK (epoch > 0),
    sequence           BIGINT NOT NULL CHECK (sequence > 0),
    previous_sequence  BIGINT NOT NULL CHECK (previous_sequence >= 0),
    schema_version     INTEGER NOT NULL CHECK (schema_version >= 1),
    key_id             TEXT NOT NULL,
    state              TEXT NOT NULL CHECK (state IN ('received','telemetry_durable','acknowledged')),
    payload_digest     TEXT NOT NULL,
    event_time_min     TIMESTAMPTZ NOT NULL,
    event_time_max     TIMESTAMPTZ NOT NULL,
    received_at        TIMESTAMPTZ NOT NULL,
    updated_at         TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, batch_id),
    FOREIGN KEY (tenant_id, stream_id) REFERENCES telemetry_delivery_streams(tenant_id, stream_id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES fleet_agents(tenant_id, id),
    FOREIGN KEY (tenant_id, asset_id) REFERENCES fleet_assets(tenant_id, id),
    CHECK (previous_sequence < sequence),
    CHECK (event_time_min <= event_time_max)
);
CREATE INDEX idx_telemetry_delivery_batches_ack
    ON telemetry_delivery_batches (tenant_id, stream_id, epoch, sequence, state);
CALL synapse_enable_tenant_rls('telemetry_delivery_batches');

-- Explicit transport holes are first-class queryable data. A filled hole is marked
-- resolved rather than deleted, preserving the fact that the hunt window was once
-- observed incomplete and later repaired by a late delivery.
CREATE TABLE telemetry_gaps (
    gap_id            BIGSERIAL PRIMARY KEY,
    tenant_id         TEXT NOT NULL REFERENCES tenants(id),
    host_id           TEXT NOT NULL,
    asset_id          TEXT NOT NULL,
    agent_id          TEXT NOT NULL,
    agent_session_id  TEXT NOT NULL,
    stream_id         TEXT NOT NULL,
    priority          SMALLINT NOT NULL CHECK (priority BETWEEN 0 AND 3),
    epoch             BIGINT NOT NULL CHECK (epoch > 0),
    from_sequence     BIGINT NOT NULL CHECK (from_sequence > 0),
    to_sequence       BIGINT NOT NULL CHECK (to_sequence >= from_sequence),
    from_at           TIMESTAMPTZ NOT NULL,
    to_at             TIMESTAMPTZ NOT NULL,
    detected_at       TIMESTAMPTZ NOT NULL,
    resolved_at       TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, stream_id) REFERENCES telemetry_delivery_streams(tenant_id, stream_id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES fleet_agents(tenant_id, id),
    FOREIGN KEY (tenant_id, asset_id) REFERENCES fleet_assets(tenant_id, id),
    CHECK (from_at <= to_at),
    CHECK (resolved_at IS NULL OR resolved_at >= detected_at)
);
CREATE UNIQUE INDEX telemetry_gaps_unresolved_uq
    ON telemetry_gaps (tenant_id, stream_id, epoch, from_sequence, to_sequence)
    WHERE resolved_at IS NULL;
CREATE INDEX idx_telemetry_gaps_hunt
    ON telemetry_gaps (tenant_id, host_id, asset_id, from_at, to_at)
    WHERE resolved_at IS NULL;
CALL synapse_enable_tenant_rls('telemetry_gaps');

-- A0.1 tail: the asset is resolved from inventory reconciliation and persisted on the
-- server. The telemetry request body never creates or changes this binding.
CREATE TABLE telemetry_asset_bindings (
    tenant_id  TEXT NOT NULL REFERENCES tenants(id),
    agent_id   TEXT NOT NULL,
    asset_id   TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, agent_id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES fleet_agents(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, asset_id) REFERENCES fleet_assets(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_telemetry_asset_bindings_asset
    ON telemetry_asset_bindings (tenant_id, asset_id);
CALL synapse_enable_tenant_rls('telemetry_asset_bindings');

-- +goose Down
-- Refuse a destructive rollback once the new transport has accepted data. There is no
-- lossless representation of Epoch/session/ACK/gap provenance in the pre-0109 schema.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM telemetry_events WHERE delivery_key IS NOT NULL)
       OR EXISTS (SELECT 1 FROM telemetry_delivery_sequences)
       OR EXISTS (SELECT 1 FROM telemetry_delivery_batches)
       OR EXISTS (SELECT 1 FROM telemetry_gaps)
       OR EXISTS (SELECT 1 FROM telemetry_asset_bindings) THEN
        RAISE EXCEPTION 'cannot roll back 0109: telemetry delivery provenance exists';
    END IF;
END $$;

DROP TABLE telemetry_asset_bindings;
DROP TABLE telemetry_gaps;
DROP TABLE telemetry_delivery_batches;
DROP TABLE telemetry_delivery_sequences;
DROP TABLE telemetry_delivery_streams;

DROP INDEX idx_telemetry_schema_version;
DROP INDEX idx_telemetry_delivery_window;
DROP INDEX idx_telemetry_legacy_sequence;
DROP INDEX telemetry_events_delivery_key_uq;
DROP INDEX telemetry_events_legacy_delivery_uq;

ALTER TABLE telemetry_events DROP CONSTRAINT telemetry_events_delivery_shape_check;
ALTER TABLE telemetry_events DROP CONSTRAINT telemetry_events_pkey;
ALTER TABLE telemetry_events ALTER COLUMN idx SET NOT NULL;
ALTER TABLE telemetry_events ADD CONSTRAINT telemetry_events_pkey PRIMARY KEY (tenant_id, host_id, class, seq, idx);
ALTER TABLE telemetry_events
    DROP COLUMN received_at,
    DROP COLUMN delivery_key,
    DROP COLUMN canonical_event,
    DROP COLUMN event_id,
    DROP COLUMN batch_id,
    DROP COLUMN epoch,
    DROP COLUMN delivery_priority,
    DROP COLUMN delivery_stream_id,
    DROP COLUMN agent_session_id,
    DROP COLUMN schema_version,
    DROP COLUMN row_id;

ALTER TABLE fleet_agents DROP CONSTRAINT fleet_agents_tenant_id_id_key;
