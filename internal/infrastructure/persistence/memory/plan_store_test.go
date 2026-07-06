package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

func planFixture(t *testing.T) agent.Plan {
	t.Helper()
	nodes := []agent.PlanNode{
		{ID: "a", Tool: "subfinder", Target: "example.com", ActionID: "act-a", Risk: agent.RiskActive},
		{ID: "b", Tool: "httpx", Target: "example.com", DependsOn: []string{"a"}, ActionID: "act-b", Risk: agent.RiskActive},
	}
	p, err := agent.NewPlan("plan-1", "sess-1", "eng-1", "goal", nodes, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPlanStore_CreateGetSaveCAS(t *testing.T) {
	ctx := context.Background()
	st := memory.NewPlanStore()
	p := planFixture(t)

	if err := st.CreatePlan(ctx, p); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Duplicate session → ErrConflict (one plan per session, fork guard).
	if err := st.CreatePlan(ctx, p); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate create must conflict, got %v", err)
	}

	got, found, err := st.GetBySession(ctx, "sess-1")
	if err != nil || !found {
		t.Fatalf("get: found=%v err=%v", found, err)
	}
	if got.Revision != 1 || len(got.Nodes) != 2 {
		t.Fatalf("unexpected plan: rev=%d nodes=%d", got.Revision, len(got.Nodes))
	}

	// SavePlan at the current revision succeeds and bumps the stored revision.
	_ = got.SetNodeStatus("a", agent.NodeDone, "")
	if err := st.SavePlan(ctx, got); err != nil {
		t.Fatalf("save: %v", err)
	}
	reloaded, _, _ := st.GetBySession(ctx, "sess-1")
	if reloaded.Revision != 2 {
		t.Fatalf("revision after save = %d, want 2", reloaded.Revision)
	}
	if n, _ := reloaded.Node("a"); n.Status != agent.NodeDone {
		t.Fatal("node status change was not persisted")
	}

	// A second SavePlan at the now-stale revision (got.Revision==1) must conflict (lost-update guard).
	if err := st.SavePlan(ctx, got); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale-revision save must conflict, got %v", err)
	}
}

func TestPlanStore_GetMissing(t *testing.T) {
	_, found, err := memory.NewPlanStore().GetBySession(context.Background(), "nope")
	if err != nil || found {
		t.Fatalf("missing plan: found=%v err=%v", found, err)
	}
}

func TestPlanStore_NoAliasing(t *testing.T) {
	ctx := context.Background()
	st := memory.NewPlanStore()
	p := planFixture(t)
	if err := st.CreatePlan(ctx, p); err != nil {
		t.Fatal(err)
	}
	// Mutating the caller's copy after create must not leak into the store.
	p.Nodes[0].Status = agent.NodeFailed
	got, _, _ := st.GetBySession(ctx, "sess-1")
	if n, _ := got.Node("a"); n.Status != agent.NodePending {
		t.Fatalf("store aliased the caller's slice: node a = %s", n.Status)
	}
}
