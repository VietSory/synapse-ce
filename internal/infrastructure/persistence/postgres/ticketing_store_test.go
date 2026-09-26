package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing/storetest"
)

func TestTicketStoreConformanceAndRLS(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate ticket schema: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	for _, tenant := range []string{"ticket-j01-a", "ticket-j01-b"} {
		suffix := "a"
		if tenant == "ticket-j01-b" {
			suffix = "b"
		}
		eng := "ticket-engagement-" + suffix
		finding := "ticket-finding-" + suffix
		integration := "ticket-integration-" + suffix
		if _, e := pool.Exec(ctx, `INSERT INTO tenants (id,name) VALUES ($1,$1) ON CONFLICT(id) DO NOTHING`, tenant); e != nil {
			t.Fatal(e)
		}
		err = WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `INSERT INTO engagements (id,tenant_id,name)
                VALUES ($1,$2,'J01 engagement') ON CONFLICT(id) DO NOTHING`, eng, tenant)
			if e != nil {
				return e
			}
			_, e = tx.Exec(ctx, `INSERT INTO findings (id,tenant_id,engagement_id,title)
                VALUES ($1,$2,$3,'J01 finding') ON CONFLICT(id) DO NOTHING`, finding, tenant, eng)
			if e != nil {
				return e
			}
			_, e = tx.Exec(ctx, `INSERT INTO integrations
                (id,tenant_id,provider,display_name,endpoint,created_at,updated_at)
                VALUES ($1,$2,'jenkins','J01 fixture','https://jenkins.example',now(),now())
                ON CONFLICT(id) DO NOTHING`, integration, tenant)
			return e
		})
		if err != nil {
			t.Fatalf("fixture %s: %v", tenant, err)
		}
	}
	t.Cleanup(func() {
		for _, tenant := range []string{"ticket-j01-a", "ticket-j01-b"} {
			_ = WithTenant(context.Background(), pool, tenant, func(tx pgx.Tx) error {
				for _, table := range []string{"ticket_intents", "ticket_links", "ticket_mappings"} {
					_, _ = tx.Exec(context.Background(), "DELETE FROM "+table+" WHERE tenant_id=$1", tenant)
				}
				_, _ = tx.Exec(context.Background(), `DELETE FROM findings WHERE tenant_id=$1 AND id LIKE 'ticket-finding-%'`, tenant)
				_, _ = tx.Exec(context.Background(), `DELETE FROM integrations WHERE tenant_id=$1 AND id LIKE 'ticket-integration-%'`, tenant)
				_, _ = tx.Exec(context.Background(), `DELETE FROM engagements WHERE tenant_id=$1 AND id LIKE 'ticket-engagement-%'`, tenant)
				return nil
			})
		}
	})
	fixture := storetest.Fixture{Tenant: "ticket-j01-a", Other: "ticket-j01-b",
		Integration: "ticket-integration-a", Engagement: "ticket-engagement-a", Finding: "ticket-finding-a"}
	storetest.Run(t, NewTicketStore(pool), fixture)
	storetest.ConcurrentReplay(t, NewTicketStore(pool), fixture)
	for _, table := range []string{"ticket_mappings", "ticket_links", "ticket_intents"} {
		var enabled, forced bool
		err = pool.QueryRow(ctx, `SELECT relrowsecurity,relforcerowsecurity
            FROM pg_class WHERE oid=$1::regclass`, table).Scan(&enabled, &forced)
		if err != nil || !enabled || !forced {
			t.Fatalf("%s RLS enabled=%v forced=%v error=%v", table, enabled, forced, err)
		}
	}
	// The default test DSN usually bypasses RLS. Verify isolation under a real
	// NOSUPERUSER / NOBYPASSRLS role, not just through WHERE tenant_id.
	const role = "ticket_j01_rls_probe"
	_, _ = pool.Exec(ctx, `DROP OWNED BY `+role)
	_, _ = pool.Exec(ctx, `DROP ROLE IF EXISTS `+role)
	for _, statement := range []string{
		`CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT,INSERT ON ticket_mappings,ticket_links,ticket_intents TO ` + role,
	} {
		if _, err = pool.Exec(ctx, statement); err != nil {
			t.Fatalf("RLS role: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP OWNED BY `+role)
		_, _ = pool.Exec(context.Background(), `DROP ROLE IF EXISTS `+role)
	})
	withRole := func(tenant string, fn func(pgx.Tx) error) error {
		return WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
			if _, e := tx.Exec(ctx, `SET LOCAL ROLE `+role); e != nil {
				return e
			}
			return fn(tx)
		})
	}
	for _, table := range []string{"ticket_mappings", "ticket_links", "ticket_intents"} {
		err = withRole("ticket-j01-b", func(tx pgx.Tx) error {
			var n int
			if e := tx.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); e != nil {
				return e
			}
			if n != 0 {
				return fmt.Errorf("tenant B saw %d rows of %s", n, table)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("RLS isolation %s: %v", table, err)
		}
	}
	err = withRole("ticket-j01-b", func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO ticket_links
            (id,tenant_id,finding_id,engagement_id,external_url,created_at)
            VALUES ('ticket-j01-forged','ticket-j01-a','ticket-finding-a',
                    'ticket-engagement-a','https://jira.example/browse/FAKE',now())`)
		return e
	})
	if err == nil {
		t.Fatal("cross-tenant forged insert passed RLS WITH CHECK")
	}
	// Bypass the domain deliberately: the database should still reject userinfo URLs.
	err = WithTenant(ctx, pool, "ticket-j01-a", func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO ticket_links
            (id,tenant_id,finding_id,engagement_id,external_url,created_at)
            VALUES ('ticket-j01-bad-url','ticket-j01-a','ticket-finding-a',
                    'ticket-engagement-a','https://user:token@jira.example/browse/SEC-1',now())`)
		return e
	})
	if err == nil {
		t.Fatal("database accepted credential-bearing link URL")
	}
	// FK constraints must reject a cross-tenant finding even under an elevated role.
	err = WithTenant(ctx, pool, "ticket-j01-b", func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO ticket_links
            (id,tenant_id,finding_id,engagement_id,external_url,created_at)
            VALUES ('ticket-j01-cross-fk','ticket-j01-b','ticket-finding-a',
                    'ticket-engagement-a','https://jira.example/browse/CROSS',now())`)
		return e
	})
	if err == nil {
		t.Fatal("cross-tenant finding passed composite FK")
	}
	_, err = NewTicketStore(pool).GetMapping(ctx, "ticket-j01-b", "ticket-j01-map-a")
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("other tenant mapping visible: %v", err)
	}
}
