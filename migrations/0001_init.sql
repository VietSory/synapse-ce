-- +goose Up
-- Initial Synapse schema. Applied in Phase 1 when the Postgres adapter replaces
-- the in-memory repositories. Multi-tenant-ready: every row carries tenant_id;
-- single-tenant mode uses a fixed default tenant row.

CREATE TABLE tenants (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE engagements (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    name            TEXT NOT NULL,
    client          TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'draft',
    authorized_from TIMESTAMPTZ,                 -- legal authorization window
    authorized_to   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_engagements_tenant ON engagements(tenant_id);

CREATE TABLE scope_targets (
    id            TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    in_scope      BOOLEAN NOT NULL,
    kind          TEXT NOT NULL,                 -- domain|ip|cidr|url|repo|image
    value         TEXT NOT NULL
);
CREATE INDEX idx_scope_engagement ON scope_targets(engagement_id);

CREATE TABLE sboms (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL REFERENCES tenants(id),
    engagement_id    TEXT REFERENCES engagements(id) ON DELETE SET NULL,
    target_ref       TEXT NOT NULL,
    source           TEXT NOT NULL,              -- e.g. syft
    tool_versions    JSONB,                      -- reproducibility (FR-A9): {syft, grype, osv, enry}
    vuln_db_snapshot TEXT,                        -- reproducibility: vuln-DB id/date used
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE components (
    id      TEXT PRIMARY KEY,
    sbom_id TEXT NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
    name    TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    purl    TEXT NOT NULL DEFAULT ''             -- component identity (PURL)
);
CREATE INDEX idx_components_sbom ON components(sbom_id);

CREATE TABLE component_licenses (
    component_id TEXT NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    spdx_id      TEXT NOT NULL,
    name         TEXT NOT NULL DEFAULT '',
    category     TEXT NOT NULL DEFAULT 'unknown' -- permissive|weak-copyleft|copyleft|proprietary|unknown
);
CREATE INDEX idx_lic_component ON component_licenses(component_id);

CREATE TABLE vulnerabilities (
    id            TEXT PRIMARY KEY,
    component_id  TEXT NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    advisory_id   TEXT NOT NULL,                 -- CVE / GHSA id
    source        TEXT NOT NULL,                 -- osv|ghsa|nvd
    severity      TEXT NOT NULL DEFAULT 'unknown',
    cvss_vector   TEXT NOT NULL DEFAULT '',
    cvss_score    DOUBLE PRECISION NOT NULL DEFAULT 0,
    kev           BOOLEAN NOT NULL DEFAULT false, -- CISA Known Exploited Vulnerabilities
    epss          DOUBLE PRECISION NOT NULL DEFAULT 0, -- exploit prediction; priority = KEV → EPSS×CVSS
    fixed_version TEXT NOT NULL DEFAULT '',
    description   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_vuln_component ON vulnerabilities(component_id);

CREATE TABLE findings (
    id             TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL REFERENCES tenants(id),
    engagement_id  TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    title          TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    severity       TEXT NOT NULL DEFAULT 'unknown',
    cvss_vector    TEXT NOT NULL DEFAULT '',
    cwe            TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'open',
    evidence_score INT NOT NULL DEFAULT 0,        -- gate applies to exploitation/AI findings only
    dedup_key      TEXT,                          -- (advisory_id, component, version) for SCA findings
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_findings_engagement ON findings(engagement_id);
CREATE UNIQUE INDEX idx_findings_dedup ON findings(engagement_id, dedup_key) WHERE dedup_key IS NOT NULL;

CREATE TABLE evidence (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL REFERENCES tenants(id),
    finding_id    TEXT REFERENCES findings(id) ON DELETE SET NULL,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL,                 -- terminal_log|screenshot|http|artifact|pcap
    sha256        TEXT NOT NULL,                 -- chain-of-custody integrity hash
    previous_hash TEXT,                          -- hash-chain link (tamper-evident); null for first item
    storage_ref   TEXT NOT NULL,                 -- object-store key
    created_by    TEXT NOT NULL DEFAULT '',      -- human user id or agent id
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_evidence_engagement ON evidence(engagement_id);

-- Append-only audit trail (SOC2-oriented). Never UPDATE/DELETE in app code.
CREATE TABLE audit_log (
    id         BIGSERIAL PRIMARY KEY,
    tenant_id  TEXT,
    actor      TEXT NOT NULL,                    -- user/agent id
    action     TEXT NOT NULL,
    target     TEXT NOT NULL,
    metadata   JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_tenant_time ON audit_log(tenant_id, created_at);

-- First-run acceptable-use acceptance (NFR-12 / ADR-0008).
CREATE TABLE aup_acceptances (
    id             TEXT PRIMARY KEY,
    actor          TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    accepted_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS aup_acceptances;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS evidence;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS vulnerabilities;
DROP TABLE IF EXISTS component_licenses;
DROP TABLE IF EXISTS components;
DROP TABLE IF EXISTS sboms;
DROP TABLE IF EXISTS scope_targets;
DROP TABLE IF EXISTS engagements;
DROP TABLE IF EXISTS tenants;
