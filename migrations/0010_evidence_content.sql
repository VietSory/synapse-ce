-- +goose Up
-- Store the sealed evidence payload so the hash-chain can be re-verified on read
-- (Phase E evidence vault). storage_ref stays for a future object-store blob ref.
ALTER TABLE evidence ADD COLUMN content BYTEA NOT NULL DEFAULT '\x'::bytea;

-- +goose Down
ALTER TABLE evidence DROP COLUMN content;
