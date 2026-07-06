package memory

import (
	"context"
	"testing"
)

func TestRunLockMutualExclusion(t *testing.T) {
	l := NewRunLock()
	ctx := context.Background()
	rel, ok, err := l.TryLock(ctx, "run1")
	if err != nil || !ok {
		t.Fatalf("first lock should succeed: ok=%v err=%v", ok, err)
	}
	if _, ok2, _ := l.TryLock(ctx, "run1"); ok2 {
		t.Fatal("a second lock on the same run must fail while held")
	}
	if _, ok3, _ := l.TryLock(ctx, "run2"); !ok3 {
		t.Fatal("a different run must be lockable concurrently")
	}
	rel() // release run1
	if _, ok4, _ := l.TryLock(ctx, "run1"); !ok4 {
		t.Fatal("run1 must be re-lockable after release")
	}
}
