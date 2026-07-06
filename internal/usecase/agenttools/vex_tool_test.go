package agenttools

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vex"
)

func TestProposeVexJustification(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	fp := &fakeJudgmentProposer{}
	c.EnableJudgments(fp)

	advertised := false
	for _, ts := range c.Tools() {
		if ts.Name == ToolProposeVexJustification {
			advertised = true
			if !json.Valid(ts.Parameters) {
				t.Error("propose_vex_justification has invalid JSON-schema parameters")
			}
		}
	}
	if !advertised {
		t.Fatal("propose_vex_justification must be advertised after EnableJudgments")
	}

	res, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
		Name:      ToolProposeVexJustification,
		Arguments: json.RawMessage(`{"finding_id":"f1","justification":"vulnerable_code_not_in_execute_path"}`),
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if res.Data == nil {
		t.Fatal("must return Data")
	}
	// recorded as PROPOSED, score 0, agent-attributed, scoped to the session engagement, about the finding
	if fp.got.EvidenceScore != 0 || fp.got.State != judgment.StateProposed || fp.got.ProposedBy != "agent:s1" {
		t.Fatalf("must record proposed/score-0/agent: %+v", fp.got)
	}
	if fp.got.Capability != judgment.CapVexJustification || fp.got.SubjectKind != judgment.SubjectFinding || fp.got.SubjectID != "f1" || fp.got.EngagementID != "eng-1" {
		t.Fatalf("subject/scope wiring wrong: %+v", fp.got)
	}
	vc, ok := fp.got.Claim.(judgment.VexJustificationClaim)
	if !ok || vc.Justification != vex.VulnerableCodeNotInExecutePath {
		t.Fatalf("claim built wrong: %#v", fp.got.Claim)
	}
}

func TestProposeVexJustificationGuards(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	// disabled (no EnableJudgments): not advertised + fail-closed dispatch.
	for _, ts := range c.Tools() {
		if ts.Name == ToolProposeVexJustification {
			t.Fatal("must not be advertised without EnableJudgments")
		}
	}
	if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolProposeVexJustification, Arguments: json.RawMessage(`{"finding_id":"f1","justification":"vulnerable_code_not_present"}`)}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("disabled tool must fail closed, got %v", err)
	}
	// enabled but missing finding_id → ErrValidation at the tool (engagement is the session's, never an arg).
	c.EnableJudgments(&fakeJudgmentProposer{})
	if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolProposeVexJustification, Arguments: json.RawMessage(`{"justification":"vulnerable_code_not_present"}`)}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("missing finding_id must fail, got %v", err)
	}
}
