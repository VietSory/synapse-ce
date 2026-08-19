package fleetdesired_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	desireddom "github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	desireduc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleetdesired"
)

type noObservedRead struct{ calls int }

func (r *noObservedRead) GetAgent(context.Context, shared.ID, shared.ID) (*fleetagent.Agent, error) {
	r.calls++
	return nil, errors.New("unexpected GetAgent")
}

func (r *noObservedRead) ListAgents(context.Context, shared.ID) ([]*fleetagent.Agent, error) {
	r.calls++
	return nil, errors.New("unexpected ListAgents")
}

func TestReconcileEmptyPolicyDoesNotReadObservedFleet(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	store := reconcileDesiredStore{rows: []*desireddom.State{{
		TenantID: "tenant", AgentID: "agent", Capabilities: []string{}, UpdatedBy: "operator",
		Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}}}
	agents := &noObservedRead{}
	svc, err := desireduc.NewService(store, agents, reconcileAudit{}, reconcileClock{now}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := svc.Reconcile(context.Background(), "tenant")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 || rows == nil {
		t.Fatalf("rows=%#v, want non-nil empty projection", rows)
	}
	if agents.calls != 0 {
		t.Fatalf("empty policy read observed fleet %d times", agents.calls)
	}
}
