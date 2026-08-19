-- +goose Up
-- Durable desired-vs-observed fleet intent (#633).
--
-- The observed `fleet_agents.capabilities` column is agent-reported and therefore must never double
-- as desired state: if an unhealthy or compromised agent stopped advertising a sensor, using the
-- observed column as policy would make the missing sensor disappear from coverage. This table holds
-- the independent operator intent that reconciliation compares against observations.
--
-- Add the composite uniqueness needed by the foreign key below. `fleet_agents.id` is already globally
-- unique; the composite key is intentionally redundant so the database itself can prove that a desired
-- row's tenant and AgentID belong together instead of relying only on an application pre-check.
ALTER TABLE fleet_agents
    ADD CONSTRAINT fleet_agents_tenant_id_id_unique UNIQUE (tenant_id, id);

CREATE TABLE fleet_desired_state (
    tenant_id    TEXT NOT NULL REFERENCES tenants(id),
    agent_id     TEXT NOT NULL,
    capabilities TEXT[] NOT NULL DEFAULT '{}',
    updated_by   TEXT NOT NULL CHECK (updated_by <> ''),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, agent_id),
    CONSTRAINT fleet_desired_state_agent_fk
        FOREIGN KEY (tenant_id, agent_id) REFERENCES fleet_agents(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fleet_desired_state_capability_bound CHECK (cardinality(capabilities) <= 64),
    CONSTRAINT fleet_desired_state_time_order CHECK (updated_at >= created_at)
);

CALL synapse_enable_tenant_rls('fleet_desired_state');

-- +goose Down
DROP TABLE fleet_desired_state;
ALTER TABLE fleet_agents DROP CONSTRAINT fleet_agents_tenant_id_id_unique;
