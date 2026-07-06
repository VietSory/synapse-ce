package memory

import (
	"context"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// RunLock is the single-process ports.RunLocker (F9): an in-memory set of currently-
// executing run ids. It guards against a same-process redelivery (the in-memory queue's
// lease expiry) re-running a run that is still in flight. Cross-process guarding requires
// the Postgres advisory-lock implementation.
type RunLock struct {
	mu     sync.Mutex
	locked map[string]bool
}

// NewRunLock returns an in-memory run locker.
func NewRunLock() *RunLock { return &RunLock{locked: map[string]bool{}} }

var _ ports.RunLocker = (*RunLock)(nil)

func (l *RunLock) TryLock(_ context.Context, runID string) (func(), bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.locked[runID] {
		return nil, false, nil
	}
	l.locked[runID] = true
	release := func() {
		l.mu.Lock()
		delete(l.locked, runID)
		l.mu.Unlock()
	}
	return release, true, nil
}
