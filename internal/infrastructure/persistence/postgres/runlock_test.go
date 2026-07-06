package postgres

import (
	"context"
	"testing"
)

// TestPostgresRunLockMutualExclusion proves F9: across connections (≈ across processes),
// only one holder of a run lease succeeds; release frees it. Gated on SYNAPSE_TEST_DB_DSN.
func TestPostgresRunLockMutualExclusion(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	l := NewRunLock(pool)
	rel, ok, err := l.TryLock(ctx, "runX")
	if err != nil || !ok {
		t.Fatalf("first lease should succeed: ok=%v err=%v", ok, err)
	}
	// A second delivery (separate connection from the pool) must NOT get the lease.
	if _, ok2, _ := l.TryLock(ctx, "runX"); ok2 {
		t.Fatal("a concurrent delivery must NOT acquire the same run lease")
	}
	rel()
	rel2, ok3, _ := l.TryLock(ctx, "runX")
	if !ok3 {
		t.Fatal("the lease must be re-acquirable after release")
	}
	rel2()
}
