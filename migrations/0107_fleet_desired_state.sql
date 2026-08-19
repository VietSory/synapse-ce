-- +goose Up
-- Durable desired-vs-observed fleet intent (#633).
--
-- The observed `fleet_agents.capabilities` column is agent-reported and therefore must never double
-- as desired state: if an unhealthy or compromised agent stopped advertising a sensor, using the
-- observed column as policy would make the missing sensor disappear from coverage. This table holds
-- the independent operator intent that reconciliation compares against observations.
--
-- Intentionally NO foreign key to fleet_agents. Desired state is operator intent and must outlive the
-- observed identity row: if an agent is later purged, retaining this row is what lets reconciliation
-- surface `agent_missing` instead of silently deleting the expectation. The mutation use case proves
-- the canonical AgentID exists in the same tenant when the intent is configured; tenant RLS remains
-- the storage isolation boundary after that observation disappears.
CREATE TABLE fleet_desired_state (
    tenant_id    TEXT NOT NULL REFERENCES tenants(id),
    agent_id     TEXT NOT NULL CHECK (agent_id <> ''),
    capabilities TEXT[] NOT NULL DEFAULT '{}',
    updated_by   TEXT NOT NULL CHECK (updated_by <> ''),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, agent_id),
    CONSTRAINT fleet_desired_state_capability_bound CHECK (cardinality(capabilities) <= 64),
    CONSTRAINT fleet_desired_state_capability_nonnull CHECK (array_position(capabilities, NULL) IS NULL),
    CONSTRAINT fleet_desired_state_time_order CHECK (updated_at >= created_at)
);

CALL synapse_enable_tenant_rls('fleet_desired_state');

-- +goose Down
DROP TABLE fleet_desired_state;
