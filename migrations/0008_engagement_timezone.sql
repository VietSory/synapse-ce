-- +goose Up
-- IANA timezone the operator entered the authorization window in (display/audit;
-- enforcement uses the absolute authorized_from/to instants). Phase C.
ALTER TABLE engagements ADD COLUMN timezone TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE engagements DROP COLUMN timezone;
