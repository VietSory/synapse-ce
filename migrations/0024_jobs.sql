-- +goose Up
-- Phase 3 (E10.2): durable job queue for the worker. Replaces the in-process jobs.Pool
-- so queued work survives restarts and a separate synapse-worker can claim it. Claimed
-- via SELECT ... FOR UPDATE SKIP LOCKED with a visibility lease (claimed_until); an
-- expired lease makes the job claimable again (at-least-once crash recovery). The
-- partial index keeps the claim query hot on the ready set only.
CREATE TABLE jobs (
    id            TEXT        PRIMARY KEY,
    kind          TEXT        NOT NULL,                 -- 'recon' | 'sca'
    payload       BYTEA       NOT NULL,                 -- opaque JSON job spec
    status        TEXT        NOT NULL DEFAULT 'queued', -- queued | claimed | done
    attempts      INT         NOT NULL DEFAULT 0,
    available_at  TIMESTAMPTZ NOT NULL DEFAULT now(),   -- not claimable before this (backoff)
    claimed_until TIMESTAMPTZ,                          -- lease expiry while claimed
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX jobs_claimable_idx ON jobs (available_at) WHERE status <> 'done';

-- +goose Down
DROP TABLE jobs;
