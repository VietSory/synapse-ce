package agenttools

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// fakeHypProposer records the proposer + input and returns a real score-0 hypothesis finding (mirrors
// exploitation.Service.ProposeHypothesis). It deliberately has NO score/verify/confirm method.
type fakeHypProposer struct {
	proposer string
	in       finding.HypothesisInput
}

func (f *fakeHypProposer) ProposeHypothesis(_ context.Context, proposer string, eng shared.ID, in finding.HypothesisInput) (finding.Finding, error) {
	f.proposer, f.in = proposer, in
	return finding.NewHypothesis("hyp-1", eng, in, proposer, time.Unix(1, 0).UTC())
}

func TestProposeAttackChain_DisabledByDefault(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	for _, ts := range c.Tools() {
		if ts.Name == ToolProposeAttackChain {
			t.Fatal("propose_attack_chain must NOT be advertised without EnableHypotheses")
		}
	}
	if _, err := c.Dispatch(context.Background(), planSession(), agent.ToolCall{Name: ToolProposeAttackChain, Arguments: json.RawMessage(`{}`)}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("disabled propose_attack_chain must error, got %v", err)
	}
}

// TestProposeAttackChain_RecordsUnprovenHypothesis: the agent records a score-0, agent-attributed,
// NON-promotable Kind=hypothesis finding, scoped to the session engagement; the catalog exposes no verify.
func TestProposeAttackChain_RecordsUnprovenHypothesis(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	fp := &fakeHypProposer{}
	c.EnableHypotheses(fp)

	advertised := false
	for _, ts := range c.Tools() {
		if ts.Name == ToolProposeAttackChain {
			advertised = true
			if !json.Valid(ts.Parameters) {
				t.Error("propose_attack_chain has invalid JSON-schema parameters")
			}
		}
	}
	if !advertised {
		t.Fatal("propose_attack_chain must be advertised after EnableHypotheses")
	}

	args := json.RawMessage(`{"title":"SSRF chain","description":"ssrf -> metadata -> admin","constituent_ids":["find:ssrf","find:meta","find:admin"]}`)
	res, err := c.Dispatch(context.Background(), planSession(), agent.ToolCall{Name: ToolProposeAttackChain, Arguments: args})
	if err != nil {
		t.Fatalf("propose_attack_chain: %v", err)
	}
	if res.Proposal != nil || res.Plan != nil || res.Data == nil {
		t.Fatal("propose_attack_chain must return only Data (a recorded claim)")
	}
	// attributed to the agent session, with the constituent ids passed through to the proposer
	if fp.proposer != "agent:s1" {
		t.Fatalf("proposer = %q, want agent:s1", fp.proposer)
	}
	if len(fp.in.ConstituentIDs) != 3 || fp.in.Title != "SSRF chain" {
		t.Fatalf("input not passed through: %+v", fp.in)
	}
	var out map[string]any
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatal(err)
	}
	if out["kind"].(string) != string(finding.KindHypothesis) || out["evidence_score"].(float64) != 0 || out["can_promote"].(bool) != false {
		t.Fatalf("a proposed hypothesis must be kind=hypothesis, score 0, not promotable, got %v", out)
	}
	if out["proposed_by"].(string) != "agent:s1" {
		t.Fatalf("proposed_by = %v, want agent:s1", out["proposed_by"])
	}
}

func TestProposeAttackChain_RejectsBadInput(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	c.EnableHypotheses(&fakeHypProposer{})
	// fewer than two constituents → the domain (NewHypothesis) rejects (a chain links >= 2 findings)
	if _, err := c.Dispatch(context.Background(), planSession(), agent.ToolCall{Name: ToolProposeAttackChain, Arguments: json.RawMessage(`{"title":"t","description":"d","constituent_ids":["only-one"]}`)}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a chain with < 2 constituents must be rejected, got %v", err)
	}
	// bad severity → rejected at the tool
	if _, err := c.Dispatch(context.Background(), planSession(), agent.ToolCall{Name: ToolProposeAttackChain, Arguments: json.RawMessage(`{"title":"t","description":"d","constituent_ids":["a","b"],"severity":"bogus"}`)}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bad severity must be rejected, got %v", err)
	}
}
