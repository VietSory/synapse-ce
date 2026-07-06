-- +goose Up
-- Phase 3 (E11): per-engagement credential vault (golden rule 3). The ciphertext column
-- holds ONLY AES-256-GCM ciphertext (base64 of nonce|ct, AAD-bound to engagement+name).
-- The master key lives in process memory (SYNAPSE_VAULT_MASTER_KEY), never in this table
-- or any log, so a database compromise alone does not yield the plaintext secrets. The
-- plaintext is resolved only at tool-execution time and substituted into the sandboxed
-- child's environment after the redacted spec is audited + sealed.
CREATE TABLE credentials (
    engagement_id TEXT        NOT NULL,
    name          TEXT        NOT NULL,                 -- [A-Za-z0-9_.-], also the {{secret:NAME}} token
    ciphertext    TEXT        NOT NULL,                 -- base64(nonce|AES-256-GCM ciphertext)
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (engagement_id, name)
);

-- +goose Down
DROP TABLE credentials;
