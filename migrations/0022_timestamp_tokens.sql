-- +goose Up
-- Phase 3 (E13): external RFC-3161 timestamp tokens for custody chain heads, stored
-- OUT-OF-BAND from the byte-deterministic report so enabling a TSA changes ZERO report
-- bytes (golden rule 5). One token per (chain, engagement, head); the external anchor
-- makes a chain tamper-PROOF (a privileged operator who reforges + re-signs is still
-- caught because they cannot backdate a trusted timestamp). engagement_id '' = the
-- global audit chain.
CREATE TABLE timestamp_tokens (
    chain         TEXT NOT NULL,                 -- 'evidence' | 'audit'
    engagement_id TEXT NOT NULL DEFAULT '',
    head          TEXT NOT NULL,                 -- the hex sha256 chain head that was anchored
    authority     TEXT NOT NULL,                 -- the issuing TSA url
    token         TEXT NOT NULL,                 -- base64-std DER RFC-3161 TimeStampToken
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (chain, engagement_id, head)
);

-- +goose Down
DROP TABLE timestamp_tokens;
