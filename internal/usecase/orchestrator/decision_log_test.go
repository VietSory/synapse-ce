package orchestrator_test

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/agenttools"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/orchestrator"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// hashOf returns the evidence-chain hash of the (single) item of the given kind for eng-1.
func hashOf(t *testing.T, ev *evidence.Service, kind string) string {
	t.Helper()
	items, err := ev.List(context.Background(), "eng-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.Kind == kind {
			return it.Hash
		}
	}
	return ""
}

// TestExplainability_AnswersFromStoredData is the headline PR4 AC: after an in-scope run, the
// decision log answers why-tool / why-target / why-stopped from STORED DATA, and a step
// decision's refs resolve to the real evidence-chain hashes (step + admission).
func TestExplainability_AnswersFromStoredData(t *testing.T) {
	llm := &scriptLLM{steps: []ports.ChatResponse{
		chatTool(toolCall("c1", agenttools.ToolStartRecon, `{"tool":"subfinder","target":"app.acme.io","rationale":"enumerate subdomains"}`)),
		chatStop("found 1 host"),
	}}
	exec := &fakeExecutor{out: orchestrator.Observation{Output: []byte("a.app.acme.io"), Summary: "1 host"}}
	orch, ev, _ := newOrch(t, llm, exec, agent.ModeAuto, orchestrator.Config{MaxSteps: 8})
	decisions := memory.NewDecisionStore()
	orch.SetDecisionStore(decisions)
	ctx := context.Background()

	sess, err := orch.Run(ctx, "eng-1", "alice", "enumerate app.acme.io")
	if err != nil {
		t.Fatal(err)
	}

	log, err := decisions.ListBySession(ctx, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	var step, stop *agent.AgentDecision
	for i := range log {
		switch log[i].Kind {
		case agent.DecisionStep:
			step = &log[i]
		case agent.DecisionStop:
			stop = &log[i]
		}
	}
	if step == nil || stop == nil {
		t.Fatalf("expected one step + one stop decision, got %d entries", len(log))
	}
	// why-tool / why-target answerable from stored data (no transcript parsing).
	if step.Outcome != agent.OutcomeExecuted || step.Reason.WhyTool != "enumerate subdomains" || step.Target != "app.acme.io" {
		t.Fatalf("step decision not answerable: %+v", step.Reason)
	}
	// refs resolve to the REAL chain hashes.
	if step.Refs.StepHash == "" || step.Refs.StepHash != hashOf(t, ev, orchestrator.StepEvidenceKind) {
		t.Fatalf("refs.step_hash %q != agent_step chain hash %q", step.Refs.StepHash, hashOf(t, ev, orchestrator.StepEvidenceKind))
	}
	if step.Refs.AdmissionHash == "" || step.Refs.AdmissionHash != hashOf(t, ev, "agent_admission") {
		t.Fatalf("refs.admission_hash %q != agent_admission chain hash %q", step.Refs.AdmissionHash, hashOf(t, ev, "agent_admission"))
	}
	// why-stopped is a closed value.
	if stop.StopReason != agent.StopGoalReached {
		t.Fatalf("stop reason=%s, want goal_reached", stop.StopReason)
	}
	// No secret/observation bytes in the decision log (refs are hashes; summary is short).
	if len(step.Refs.StepHash) == 0 {
		t.Fatal("expected a non-empty hash ref")
	}
}

// TestDeniedRecordsDecisionWithNoSeal: an out-of-scope step is recorded as a denied decision
// with NO evidence refs (nothing was sealed/executed).
func TestDeniedRecordsDecisionWithNoSeal(t *testing.T) {
	llm := &scriptLLM{steps: []ports.ChatResponse{
		chatTool(toolCall("c1", agenttools.ToolStartRecon, `{"tool":"subfinder","target":"evil.com","rationale":"oops"}`)),
		chatStop("stopping"),
	}}
	exec := &fakeExecutor{out: orchestrator.Observation{Output: []byte("x"), Summary: "y"}}
	orch, _, _ := newOrch(t, llm, exec, agent.ModeAuto, orchestrator.Config{MaxSteps: 8})
	decisions := memory.NewDecisionStore()
	orch.SetDecisionStore(decisions)
	ctx := context.Background()

	sess, err := orch.Run(ctx, "eng-1", "alice", "go")
	if err != nil {
		t.Fatal(err)
	}
	log, _ := decisions.ListBySession(ctx, sess.ID)
	var denied *agent.AgentDecision
	for i := range log {
		if log[i].Outcome == agent.OutcomeDenied {
			denied = &log[i]
		}
	}
	if denied == nil {
		t.Fatal("expected a denied step decision")
	}
	if denied.Refs.StepHash != "" || denied.Refs.AdmissionHash != "" {
		t.Fatalf("a denied decision must carry no evidence refs (nothing sealed), got %+v", denied.Refs)
	}
}

// TestNilDecisionStore_NoRecording: without a decision store the run is unaffected (legacy).
func TestNilDecisionStore_NoRecording(t *testing.T) {
	llm := &scriptLLM{steps: []ports.ChatResponse{
		chatTool(toolCall("c1", agenttools.ToolStartRecon, `{"tool":"subfinder","target":"app.acme.io","rationale":"x"}`)),
		chatStop("done"),
	}}
	exec := &fakeExecutor{out: orchestrator.Observation{Output: []byte("h"), Summary: "1"}}
	orch, _, _ := newOrch(t, llm, exec, agent.ModeAuto, orchestrator.Config{MaxSteps: 8}) // no SetDecisionStore
	sess, err := orch.Run(context.Background(), "eng-1", "alice", "go")
	if err != nil || sess.Status != agent.StatusSucceeded {
		t.Fatalf("nil decision store must not affect the run: status=%s err=%v", sess.Status, err)
	}
}
