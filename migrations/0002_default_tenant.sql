-- +goose Up
-- Default tenant for single-tenant mode (engagements use tenant_id '').
INSERT INTO tenants (id, name) VALUES ('', 'default') ON CONFLICT (id) DO NOTHING;

-- +goose Down
DELETE FROM tenants WHERE id = '';
