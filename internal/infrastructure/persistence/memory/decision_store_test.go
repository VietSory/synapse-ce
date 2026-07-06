package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

func TestDecisionStore_AppendListSeqAndIdempotency(t *testing.T) {
	ctx := context.Background()
	st := memory.NewDecisionStore()
	now := time.Unix(1, 0).UTC()
	step := func(actionID string) agent.AgentDecision {
		d, _ := agent.NewStepDecision("s1", "e1", agent.OutcomeExecuted, shared.ID(actionID), "start_recon", "recon.subfinder", "app.acme.io", agent.RiskActive, "auto", agent.AgentReason{}, agent.AgentEvidenceRefs{StepHash: "h"}, "agent:s1", now)
		return d
	}

	if err := st.AppendDecision(ctx, step("a1")); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendDecision(ctx, step("a2")); err != nil {
		t.Fatal(err)
	}
	// Re-record the same action id → idempotent no-op (a redelivered drive cannot fork the log).
	if err := st.AppendDecision(ctx, step("a1")); err != nil {
		t.Fatal(err)
	}
	stop, _ := agent.NewStopDecision("s1", "e1", agent.StopGoalReached, "done", "agent:s1", now)
	if err := st.AppendDecision(ctx, stop); err != nil {
		t.Fatal(err)
	}
	// A second stop → idempotent no-op (one stop per session).
	if err := st.AppendDecision(ctx, stop); err != nil {
		t.Fatal(err)
	}

	got, err := st.ListBySession(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 { // a1, a2, stop
		t.Fatalf("expected 3 decisions (dedup'd), got %d", len(got))
	}
	// seq is monotonic in append order.
	for i, d := range got {
		if d.Seq != i {
			t.Fatalf("decision[%d] seq=%d, want %d", i, d.Seq, i)
		}
	}
	if got[2].Kind != agent.DecisionStop {
		t.Fatalf("last decision kind=%s, want stop", got[2].Kind)
	}
}
