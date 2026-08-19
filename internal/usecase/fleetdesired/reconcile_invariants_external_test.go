package fleetdesired_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	desireddom "github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	desireduc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type reconcileClock struct{ now time.Time }

func (c reconcileClock) Now() time.Time { return c.now }

type reconcileAudit struct{}

func (reconcileAudit) Record(context.Context, ports.AuditEntry) error { return nil }

type reconcileDesiredStore struct {
	rows []*desireddom.State
}

func (s reconcileDesiredStore) Get(context.Context, shared.ID, shared.ID) (*desireddom.State, error) {
	return nil, shared.ErrNotFound
}
func (s reconcileDesiredStore) Put(context.Context, *desireddom.State) error { return nil }
func (s reconcileDesiredStore) List(context.Context, shared.ID) ([]*desireddom.State, error) {
	return s.rows, nil
}

type reconcileAgentReader struct {
	rows []*fleetagent.Agent
}

func (s reconcileAgentReader) GetAgent(context.Context, shared.ID, shared.ID) (*fleetagent.Agent, error) {
	return nil, shared.ErrNotFound
}
func (s reconcileAgentReader) ListAgents(context.Context, shared.ID) ([]*fleetagent.Agent, error) {
	return s.rows, nil
}

func desiredFixture(id string, caps []string, now time.Time) *desireddom.State {
	return &desireddom.State{
		TenantID: "tenant", AgentID: shared.ID(id), Capabilities: caps, UpdatedBy: "operator",
		Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
}

func agentFixture(id string, caps []string, lastSeen time.Time) *fleetagent.Agent {
	return &fleetagent.Agent{
		ID: shared.ID(id), TenantID: "tenant", Capabilities: caps,
		LastSeenAt: lastSeen, State: fleetagent.StateActive,
	}
}

func TestReconcileCanonicalizesObservedCapabilitiesAndDoesNotMutateDesiredOrder(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	z := desiredFixture("z-agent", []string{"process"}, now)
	a := desiredFixture("a-agent", []string{"network", "process"}, now)
	desired := []*desireddom.State{z, a} // deliberately not store order: reconciler must stay deterministic
	agents := []*fleetagent.Agent{
		agentFixture("a-agent", []string{" process ", "network"}, now),
	}
	svc, err := desireduc.NewService(reconcileDesiredStore{rows: desired}, reconcileAgentReader{rows: agents}, reconcileAudit{}, reconcileClock{now}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := svc.Reconcile(context.Background(), "tenant")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"a-agent/network/true/",
		"a-agent/process/true/",
		"z-agent/process/false/agent_missing",
	}
	if len(rows) != len(want) {
		t.Fatalf("got %d rows: %#v", len(rows), rows)
	}
	for i, row := range rows {
		got := fmt.Sprintf("%s/%s/%t/%s", row.AgentID, row.Capability, row.Covered, row.GapReason)
		if got != want[i] {
			t.Fatalf("row[%d]=%q want %q", i, got, want[i])
		}
	}
	if desired[0] != z || desired[1] != a {
		t.Fatal("reconciliation mutated the store-owned desired slice")
	}
}

func TestReconcileFailsClosedOnMalformedSnapshots(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	valid := desiredFixture("agent", []string{"process"}, now)
	cases := []struct {
		name    string
		desired []*desireddom.State
		agents  []*fleetagent.Agent
	}{
		{name: "nil desired", desired: []*desireddom.State{nil}},
		{name: "cross-tenant desired", desired: []*desireddom.State{{
			TenantID: "other", AgentID: "agent", Capabilities: []string{"process"}, UpdatedBy: "operator",
			Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
		}}},
		{name: "duplicate desired", desired: []*desireddom.State{valid, valid}},
		{name: "nil observed", desired: []*desireddom.State{valid}, agents: []*fleetagent.Agent{nil}},
		{name: "cross-tenant observed", desired: []*desireddom.State{valid}, agents: []*fleetagent.Agent{{
			ID: "agent", TenantID: "other", LastSeenAt: now, State: fleetagent.StateActive,
		}}},
		{name: "duplicate observed", desired: []*desireddom.State{valid}, agents: []*fleetagent.Agent{
			agentFixture("agent", nil, now), agentFixture("agent", nil, now),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, err := desireduc.NewService(reconcileDesiredStore{rows: tc.desired}, reconcileAgentReader{rows: tc.agents}, reconcileAudit{}, reconcileClock{now}, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			_, err = svc.Reconcile(context.Background(), "tenant")
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("Reconcile error=%v, want validation error", err)
			}
		})
	}
}

func BenchmarkReconcileTenThousandAgents(b *testing.B) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	caps := []string{"file", "network", "privilege", "process"}
	desired := make([]*desireddom.State, 0, 10_000)
	agents := make([]*fleetagent.Agent, 0, 10_000)
	for i := 0; i < 10_000; i++ {
		id := fmt.Sprintf("agent-%05d", i)
		desired = append(desired, desiredFixture(id, caps, now))
		agents = append(agents, agentFixture(id, caps, now))
	}
	svc, err := desireduc.NewService(reconcileDesiredStore{rows: desired}, reconcileAgentReader{rows: agents}, reconcileAudit{}, reconcileClock{now}, time.Minute)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rows, err := svc.Reconcile(context.Background(), "tenant")
		if err != nil || len(rows) != 40_000 {
			b.Fatalf("rows=%d err=%v", len(rows), err)
		}
	}
}

func BenchmarkGapsHealthyTenThousandAgents(b *testing.B) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	caps := []string{"file", "network", "privilege", "process"}
	desired := make([]*desireddom.State, 0, 10_000)
	agents := make([]*fleetagent.Agent, 0, 10_000)
	for i := 0; i < 10_000; i++ {
		id := fmt.Sprintf("agent-%05d", i)
		desired = append(desired, desiredFixture(id, caps, now))
		agents = append(agents, agentFixture(id, caps, now))
	}
	svc, err := desireduc.NewService(reconcileDesiredStore{rows: desired}, reconcileAgentReader{rows: agents}, reconcileAudit{}, reconcileClock{now}, time.Minute)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rows, err := svc.Gaps(context.Background(), "tenant")
		if err != nil || len(rows) != 0 {
			b.Fatalf("rows=%d err=%v", len(rows), err)
		}
	}
}
