package agent

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var planNow = time.Unix(1_700_000_000, 0).UTC()

func nd(id string, deps ...string) PlanNode {
	return PlanNode{ID: id, Tool: "subfinder", Target: "example.com", DependsOn: deps, ActionID: shared.ID("act-" + id), Risk: RiskActive}
}

func mustPlan(t *testing.T, nodes ...PlanNode) Plan {
	t.Helper()
	p, err := NewPlan("plan-1", "sess-1", "eng-1", "goal", nodes, planNow)
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	return p
}

func TestNewPlan_Valid(t *testing.T) {
	p := mustPlan(t, nd("a"), nd("b", "a"), nd("c", "a", "b"))
	if p.Status != PlanActive || p.Revision != 1 || len(p.Nodes) != 3 {
		t.Fatalf("unexpected plan: status=%s rev=%d nodes=%d", p.Status, p.Revision, len(p.Nodes))
	}
	for _, n := range p.Nodes {
		if n.Status != NodePending {
			t.Fatalf("node %s status=%s, want pending", n.ID, n.Status)
		}
		if n.MaxRetries != defaultNodeMaxRetries {
			t.Fatalf("node %s MaxRetries=%d, want %d", n.ID, n.MaxRetries, defaultNodeMaxRetries)
		}
	}
}

func TestNewPlan_Rejections(t *testing.T) {
	cases := map[string][]PlanNode{
		"empty":          {},
		"self-dep":       {nd("a", "a")},
		"unknown-dep":    {nd("a", "ghost")},
		"duplicate-id":   {nd("a"), nd("a")},
		"two-cycle":      {nd("a", "b"), nd("b", "a")},
		"three-cycle":    {nd("a", "c"), nd("b", "a"), nd("c", "b")},
		"missing-tool":   {{ID: "a", Target: "x", ActionID: "act-a"}},
		"missing-target": {{ID: "a", Tool: "subfinder", ActionID: "act-a"}},
		"dup-dep":        {nd("a"), {ID: "b", Tool: "subfinder", Target: "x", DependsOn: []string{"a", "a"}}},
	}
	for name, nodes := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewPlan("p", "s", "e", "g", nodes, planNow); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("expected ErrValidation, got %v", err)
			}
		})
	}
}

func TestNewPlan_Oversize(t *testing.T) {
	nodes := make([]PlanNode, MaxPlanNodes+1)
	for i := range nodes {
		nodes[i] = nd(string(rune('a'+i%26)) + string(rune('0'+i/26)))
	}
	if _, err := NewPlan("p", "s", "e", "g", nodes, planNow); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("oversize plan must be rejected, got %v", err)
	}
}

func TestNewPlan_Fanout(t *testing.T) {
	var deps []string
	nodes := []PlanNode{}
	for i := 0; i <= MaxNodeFanout; i++ {
		id := "d" + string(rune('A'+i))
		nodes = append(nodes, nd(id))
		deps = append(deps, id)
	}
	nodes = append(nodes, PlanNode{ID: "hub", Tool: "subfinder", Target: "x", DependsOn: deps, ActionID: "act-hub"})
	if _, err := NewPlan("p", "s", "e", "g", nodes, planNow); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("over-fanout node must be rejected, got %v", err)
	}
}

func TestPlan_Ready_RespectsDepsAndRetryCap(t *testing.T) {
	p := mustPlan(t, nd("a"), nd("b", "a"))
	// Only 'a' is ready (b waits on a).
	if got := p.Ready(); len(got) != 1 || got[0] != "a" {
		t.Fatalf("ready=%v, want [a]", got)
	}
	// Mark a done → b becomes ready.
	_ = p.SetNodeStatus("a", NodeDone, "")
	if got := p.Ready(); len(got) != 1 || got[0] != "b" {
		t.Fatalf("ready=%v, want [b]", got)
	}
	// A node at its retry cap is not ready even with deps met.
	p2 := mustPlan(t, nd("x"))
	p2.Nodes[0].Retries = p2.Nodes[0].MaxRetries
	if got := p2.Ready(); len(got) != 0 {
		t.Fatalf("retry-exhausted node must not be ready, got %v", got)
	}
}

func TestPlan_PropagateFailures_FixedPoint(t *testing.T) {
	// a → b → c chain; a fails → b and c both skipped (transitive).
	p := mustPlan(t, nd("a"), nd("b", "a"), nd("c", "b"))
	_ = p.SetNodeStatus("a", NodeFailed, "boom")
	changed := p.PropagateFailures()
	if len(changed) != 2 {
		t.Fatalf("expected 2 skipped (b,c), got %v", changed)
	}
	for _, id := range []string{"b", "c"} {
		n, _ := p.Node(id)
		if n.Status != NodeSkipped {
			t.Fatalf("node %s status=%s, want skipped", id, n.Status)
		}
	}
}

func TestPlan_PropagateFailures_DoneDepDoesNotCascade(t *testing.T) {
	p := mustPlan(t, nd("a"), nd("b", "a"))
	_ = p.SetNodeStatus("a", NodeDone, "")
	if changed := p.PropagateFailures(); len(changed) != 0 {
		t.Fatalf("a done dep must not cascade a skip, got %v", changed)
	}
}

func TestPlan_RecomputeStatus(t *testing.T) {
	p := mustPlan(t, nd("a"), nd("b", "a"))
	if p.RecomputeStatus() != PlanActive {
		t.Fatal("unsettled plan must stay active")
	}
	_ = p.SetNodeStatus("a", NodeDone, "")
	_ = p.SetNodeStatus("b", NodeDone, "")
	if p.RecomputeStatus() != PlanComplete {
		t.Fatal("all-done plan must be complete")
	}
	// Failed path.
	p2 := mustPlan(t, nd("a"), nd("b", "a"))
	_ = p2.SetNodeStatus("a", NodeDenied, "out of scope")
	p2.PropagateFailures()
	if p2.RecomputeStatus() != PlanFailed {
		t.Fatal("a denied node + skipped dependent must be PlanFailed")
	}
	// Never un-settles.
	prev := p2.Status
	_ = p2.SetNodeStatus("a", NodeDone, "")
	if p2.RecomputeStatus() != prev {
		t.Fatal("RecomputeStatus must never move a plan out of a terminal status")
	}
}

func TestPlan_AwaitingAndSettled(t *testing.T) {
	p := mustPlan(t, nd("a"), nd("b"))
	if p.AllSettled() || p.AwaitingApproval() {
		t.Fatal("fresh plan is neither settled nor awaiting")
	}
	_ = p.SetNodeStatus("a", NodeAwaiting, "")
	if !p.AwaitingApproval() {
		t.Fatal("expected AwaitingApproval")
	}
	if id := p.FirstUnsettledClaimed(); id != "a" {
		t.Fatalf("firstUnsettledClaimed=%q, want a", id)
	}
	_ = p.SetNodeStatus("a", NodeDone, "")
	_ = p.SetNodeStatus("b", NodeFailed, "x")
	if !p.AllSettled() {
		t.Fatal("expected AllSettled")
	}
}

func TestAppendNodes_RejectsDeadDeps_NeverMutatesDone(t *testing.T) {
	p := mustPlan(t, nd("a"), nd("b", "a"))
	_ = p.SetNodeStatus("a", NodeDone, "")
	_ = p.SetNodeStatus("b", NodeFailed, "boom")

	// Appending a node that depends on the FAILED node b is rejected (dead dependency).
	if err := p.AppendNodes([]PlanNode{nd("c", "b")}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("dep on a failed node must be rejected, got %v", err)
	}
	// Existing nodes are untouched by the failed append.
	if n, _ := p.Node("a"); n.Status != NodeDone {
		t.Fatal("AppendNodes must not mutate an existing node")
	}
	// Appending a node that depends on the DONE node a succeeds.
	if err := p.AppendNodes([]PlanNode{nd("d", "a")}); err != nil {
		t.Fatalf("dep on a done node must be allowed: %v", err)
	}
	if len(p.Nodes) != 3 {
		t.Fatalf("expected 3 nodes after append, got %d", len(p.Nodes))
	}
	// A cyclic / duplicate append is rejected over the union.
	if err := p.AppendNodes([]PlanNode{nd("a")}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("duplicate id append must be rejected, got %v", err)
	}
}

func TestNodeStatus_TerminalAndBlocks(t *testing.T) {
	for _, s := range []NodeStatus{NodeDone, NodeDenied, NodeSkipped, NodeFailed} {
		if !s.Terminal() {
			t.Fatalf("%s must be terminal", s)
		}
	}
	for _, s := range []NodeStatus{NodePending, NodeRunning, NodeAwaiting} {
		if s.Terminal() {
			t.Fatalf("%s must not be terminal", s)
		}
	}
	if NodeDone.blocksDependents() {
		t.Fatal("done must not block dependents")
	}
	for _, s := range []NodeStatus{NodeDenied, NodeSkipped, NodeFailed} {
		if !s.blocksDependents() {
			t.Fatalf("%s must block dependents", s)
		}
	}
}

func TestPlan_ReadyActive_ExcludesIntrusiveAndCaps(t *testing.T) {
	a := nd("a")
	a.Risk = RiskActive
	b := nd("b")
	b.Risk = RiskActive
	intr := nd("c")
	intr.Risk = RiskIntrusive
	p := mustPlan(t, a, b, intr)
	got := p.ReadyActive(4)
	if len(got) != 2 {
		t.Fatalf("ReadyActive must exclude the intrusive node, got %v", got)
	}
	for _, id := range got {
		n, _ := p.Node(id)
		if n.Risk != RiskActive {
			t.Fatalf("node %s risk=%s in active batch", id, n.Risk)
		}
	}
	// cap respected
	if capped := p.ReadyActive(1); len(capped) != 1 {
		t.Fatalf("ReadyActive cap not respected, got %d", len(capped))
	}
	if none := p.ReadyActive(0); none != nil {
		t.Fatalf("ReadyActive(0) must return nothing, got %v", none)
	}
}

func TestSetNodeStatus_UnknownID(t *testing.T) {
	p := mustPlan(t, nd("a"))
	if err := p.SetNodeStatus("ghost", NodeDone, ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown node id must error, got %v", err)
	}
}
