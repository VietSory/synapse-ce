package agenttools

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func planSession() agent.Session {
	return agent.Session{ID: "s1", EngagementID: "eng-1", InitiatedBy: "alice", Goal: "enumerate app.example.com"}
}

// TestProposePlan_DisabledByDefault: without EnablePlanning the tool is neither advertised nor
// dispatchable (the catalog never offers a capability the orchestrator can't drive).
func TestProposePlan_DisabledByDefault(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	for _, ts := range c.Tools() {
		if ts.Name == ToolProposePlan {
			t.Fatal("propose_plan must NOT be advertised when planning is disabled")
		}
	}
	_, err := c.Dispatch(context.Background(), planSession(), agent.ToolCall{Name: ToolProposePlan, Arguments: json.RawMessage(`{"nodes":[]}`)})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("disabled propose_plan must error, got %v", err)
	}
}

// TestProposePlan_EnabledAdvertisesExactly: enabling planning adds propose_plan and nothing
// else (the allowlist stays read + propose-only).
func TestProposePlan_EnabledAdvertisesExactly(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	c.EnablePlanning()
	got := map[string]bool{}
	for _, ts := range c.Tools() {
		got[ts.Name] = true
	}
	want := []string{ToolListFindings, ToolGetFindingDetail, ToolListSASTValidation, ToolPlanRuntimeVerification, ToolListEvidence, ToolVerifyCustody, ToolListReconTools, ToolStartRecon, ToolEvidenceSufficiency, ToolProposePlan}
	if len(got) != len(want) {
		t.Fatalf("advertised %d tools, want %d: %v", len(got), len(want), got)
	}
	if !got[ToolProposePlan] {
		t.Fatal("propose_plan must be advertised after EnablePlanning")
	}
}

// TestProposePlan_MintsIDsClassifiesRiskRunsNothing is the core PR3 anti-self-escalation +
// validation guarantee: Go mints node ids (not the LLM keys) + ActionIDs, classifies risk in
// Go, translates dependency keys to ids, and the plan executes NOTHING (it is a proposal).
func TestProposePlan_MintsIDsClassifiesRiskRunsNothing(t *testing.T) {
	c, audit := newCatalog(t, nil, nil, subfinder(), naabu())
	c.EnablePlanning()
	args := json.RawMessage(`{"nodes":[
		{"key":"enum","tool":"subfinder","target":"example.com","rationale":"find subdomains"},
		{"key":"scan","tool":"naabu","target":"example.com","depends_on":["enum"],"rationale":"port scan"}
	]}`)
	res, err := c.Dispatch(context.Background(), planSession(), agent.ToolCall{Name: ToolProposePlan, Arguments: args})
	if err != nil {
		t.Fatalf("propose_plan: %v", err)
	}
	if res.Plan == nil || res.Proposal != nil || res.Data != nil {
		t.Fatal("propose_plan must return only a Plan")
	}
	p := *res.Plan
	if len(p.Nodes) != 2 || p.Status != agent.PlanActive {
		t.Fatalf("unexpected plan: nodes=%d status=%s", len(p.Nodes), p.Status)
	}
	enum, scan := p.Nodes[0], p.Nodes[1]
	// Node ids are Go-minted (seqIDs → "id-N"), never the LLM keys.
	if enum.ID == "enum" || scan.ID == "scan" || enum.ID == "" || scan.ID == "" {
		t.Fatalf("node ids must be Go-minted, got %q/%q", enum.ID, scan.ID)
	}
	// Dependency key "enum" was translated to enum's minted id.
	if len(scan.DependsOn) != 1 || scan.DependsOn[0] != enum.ID {
		t.Fatalf("dep not translated to minted id: %v (want [%s])", scan.DependsOn, enum.ID)
	}
	// Risk classified in Go: subfinder=active, naabu(capability-sensitive)=intrusive.
	if enum.Risk != agent.RiskActive || scan.Risk != agent.RiskIntrusive {
		t.Fatalf("risk misclassified: enum=%s scan=%s", enum.Risk, scan.Risk)
	}
	// Each node has a stable minted ActionID.
	if enum.ActionID == "" || scan.ActionID == "" || enum.ActionID == scan.ActionID {
		t.Fatalf("each node needs a distinct ActionID, got %q/%q", enum.ActionID, scan.ActionID)
	}
	// All nodes start pending (nothing executed).
	for _, n := range p.Nodes {
		if n.Status != agent.NodePending {
			t.Fatalf("node %s status=%s, want pending (propose runs nothing)", n.ID, n.Status)
		}
	}
	// Audited as the agent, action agent.propose_plan.
	found := false
	for _, r := range audit.recs {
		if r.Action == "agent.propose_plan" {
			found = true
		}
	}
	if !found {
		t.Fatal("propose_plan must be audited as agent.propose_plan")
	}
}

func TestProposePlan_Rejections(t *testing.T) {
	cases := map[string]string{
		"cycle":        `{"nodes":[{"key":"a","tool":"subfinder","target":"example.com","depends_on":["b"]},{"key":"b","tool":"subfinder","target":"example.com","depends_on":["a"]}]}`,
		"unknown-tool": `{"nodes":[{"key":"a","tool":"ghosttool","target":"example.com"}]}`,
		"unknown-dep":  `{"nodes":[{"key":"a","tool":"subfinder","target":"example.com","depends_on":["nope"]}]}`,
		"dup-key":      `{"nodes":[{"key":"a","tool":"subfinder","target":"example.com"},{"key":"a","tool":"subfinder","target":"example.com"}]}`,
		"bad-target":   `{"nodes":[{"key":"a","tool":"subfinder","target":"-oG/etc/passwd"}]}`,
		"empty":        `{"nodes":[]}`,
		"missing-key":  `{"nodes":[{"tool":"subfinder","target":"example.com"}]}`,
		"wrong-kind":   `{"nodes":[{"key":"a","tool":"subfinder","target":"1.2.3.4"}]}`,
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			c, _ := newCatalog(t, nil, nil, subfinder(), naabu())
			c.EnablePlanning()
			_, err := c.Dispatch(context.Background(), planSession(), agent.ToolCall{Name: ToolProposePlan, Arguments: json.RawMessage(args)})
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("expected ErrValidation, got %v", err)
			}
		})
	}
}

// TestProposeForNode_StableActionIDAndArgv: the orchestrator rebuilds a node's proposal with
// the node's stable ActionID and the exact argv start_recon would use.
func TestProposeForNode_StableActionIDAndArgv(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	c.EnablePlanning()
	node := agent.PlanNode{ID: "n1", Tool: "subfinder", Target: "example.com", ActionID: "act-stable", Risk: agent.RiskActive}
	prop, err := c.ProposeForNode(planSession(), node)
	if err != nil {
		t.Fatalf("ProposeForNode: %v", err)
	}
	if prop.ID != "act-stable" {
		t.Fatalf("proposal must reuse the node's stable ActionID, got %q", prop.ID)
	}
	if prop.Tool != ToolStartRecon || prop.Action != "recon.subfinder" {
		t.Fatalf("unexpected proposal tool/action: %q/%q", prop.Tool, prop.Action)
	}
	wantArgv := []string{"subfinder", "-silent", "-json", "-d", "example.com"}
	if len(prop.Argv) != len(wantArgv) {
		t.Fatalf("argv=%v, want %v", prop.Argv, wantArgv)
	}
	for i := range wantArgv {
		if prop.Argv[i] != wantArgv[i] {
			t.Fatalf("argv[%d]=%q, want %q", i, prop.Argv[i], wantArgv[i])
		}
	}
	// A node with no ActionID is rejected (can't run an unkeyed node).
	if _, err := c.ProposeForNode(planSession(), agent.PlanNode{ID: "x", Tool: "subfinder", Target: "example.com"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("node without ActionID must error, got %v", err)
	}
}
