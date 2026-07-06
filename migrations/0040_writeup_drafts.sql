-- +goose Up
-- writeup_drafts: AI-proposed, human-gated finding write-up drafts (E31.1). A draft is mutable
-- working data (propose -> edit -> accept/reject), so Save upserts by id; it is NOT append-only
-- (the append-only record of each change is the audit log). tenant_id is present so the P5/E22
-- row-scoping sweep covers this table uniformly; reads are tenant-isolated via the engagement gate.
CREATE TABLE writeup_drafts (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL REFERENCES tenants(id),
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    finding_id    TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    remediation   TEXT NOT NULL DEFAULT '',
    state         TEXT NOT NULL,
    proposed_by   TEXT NOT NULL DEFAULT '',
    decided_by    TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_writeup_drafts_engagement ON writeup_drafts(engagement_id);
CREATE INDEX idx_writeup_drafts_tenant ON writeup_drafts(tenant_id);

-- +goose Down
DROP TABLE IF EXISTS writeup_drafts;
