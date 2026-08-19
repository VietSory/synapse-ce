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
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type setInvariantStore struct {
	current *desireddom.State
	getErr  error
	puts    int
	written *desireddom.State
}

func (s *setInvariantStore) Get(context.Context, shared.ID, shared.ID) (*desireddom.State, error) {
	return s.current, s.getErr
}

func (s *setInvariantStore) Put(_ context.Context, state *desireddom.State) error {
	s.puts++
	s.written = state
	return nil
}

func (*setInvariantStore) List(context.Context, shared.ID) ([]*desireddom.State, error) { return nil, nil }

type setInvariantAgentReader struct {
	err   error
	calls int
}

func (r *setInvariantAgentReader) GetAgent(context.Context, shared.ID, shared.ID) (*fleetagent.Agent, error) {
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	return &fleetagent.Agent{ID: "agent", TenantID: "tenant"}, nil
}

func (*setInvariantAgentReader) ListAgents(context.Context, shared.ID) ([]*fleetagent.Agent, error) {
	return nil, nil
}

type setInvariantAudit struct{ records int }

func (a *setInvariantAudit) Record(context.Context, ports.AuditEntry) error {
	a.records++
	return nil
}

type setInvariantClock struct {
	now   time.Time
	calls int
}

func (c *setInvariantClock) Now() time.Time {
	c.calls++
	return c.now
}

func setInvariantState(now time.Time) *desireddom.State {
	return &desireddom.State{
		TenantID: "tenant", AgentID: "agent", Capabilities: []string{"network", "process"}, UpdatedBy: "operator",
		Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
}

func TestSetDesiredCapabilitiesIdenticalReapplyIsSideEffectFree(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	current := setInvariantState(now)
	store := &setInvariantStore{current: current}
	agents := &setInvariantAgentReader{err: errors.New("existing intent must not depend on observed agent")}
	audit := &setInvariantAudit{}
	clock := &setInvariantClock{now: now.Add(time.Hour)}
	svc, err := desireduc.NewService(store, agents, audit, clock, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	got, err := svc.SetDesiredCapabilities(context.Background(), desireduc.SetInput{
		TenantID: "tenant", AgentID: "agent", Actor: "another-operator",
		Capabilities: []string{" process ", "network", "process"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if store.puts != 0 || agents.calls != 0 || audit.records != 0 || clock.calls != 0 {
		t.Fatalf("identical reapply caused side effects: puts=%d agent_reads=%d audit=%d clock=%d",
			store.puts, agents.calls, audit.records, clock.calls)
	}
	if got != current || !got.Audit.UpdatedAt.Equal(now) {
		t.Fatalf("identical reapply did not return unchanged state: %+v", got)
	}
}

func TestSetDesiredCapabilitiesCanClearIntentAfterObservedAgentDisappears(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	store := &setInvariantStore{current: setInvariantState(now)}
	agents := &setInvariantAgentReader{err: shared.ErrNotFound}
	audit := &setInvariantAudit{}
	clock := &setInvariantClock{now: now.Add(time.Hour)}
	svc, err := desireduc.NewService(store, agents, audit, clock, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	got, err := svc.SetDesiredCapabilities(context.Background(), desireduc.SetInput{
		TenantID: "tenant", AgentID: "agent", Actor: "operator", Capabilities: nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if agents.calls != 0 {
		t.Fatalf("existing intent unexpectedly depended on observed agent: reads=%d", agents.calls)
	}
	if store.puts != 1 || audit.records != 1 || clock.calls != 1 {
		t.Fatalf("clear side effects mismatch: puts=%d audit=%d clock=%d", store.puts, audit.records, clock.calls)
	}
	if got != store.written || len(got.Capabilities) != 0 || !got.Audit.CreatedAt.Equal(now) || !got.Audit.UpdatedAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("cleared state mismatch: %+v", got)
	}
}

func TestSetDesiredCapabilitiesStillRequiresObservedAgentForNewIntent(t *testing.T) {
	store := &setInvariantStore{getErr: shared.ErrNotFound}
	agents := &setInvariantAgentReader{err: shared.ErrNotFound}
	audit := &setInvariantAudit{}
	clock := &setInvariantClock{now: time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)}
	svc, err := desireduc.NewService(store, agents, audit, clock, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.SetDesiredCapabilities(context.Background(), desireduc.SetInput{
		TenantID: "tenant", AgentID: "missing", Actor: "operator", Capabilities: []string{"process"},
	})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("error=%v, want ErrNotFound", err)
	}
	if agents.calls != 1 || store.puts != 0 || audit.records != 0 || clock.calls != 0 {
		t.Fatalf("new missing-agent intent side effects mismatch: agent_reads=%d puts=%d audit=%d clock=%d",
			agents.calls, store.puts, audit.records, clock.calls)
	}
}
