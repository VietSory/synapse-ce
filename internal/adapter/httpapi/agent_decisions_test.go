package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/logging"
)

// TestListAgentDecisions_EngagementScoped: the decision log is returned for a session, scoped to
// its engagement (a mismatched engagement id is a 404), and is read-only structured data.
func TestListAgentDecisions_EngagementScoped(t *testing.T) {
	ctx := context.Background()
	sessions := memory.NewAgentSessionStore()
	now := time.Unix(1_000, 0).UTC()
	sess, err := agent.NewSession("sess-1", "eng-1", "alice", "goal", "m", "", "", now, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := sessions.SaveSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	decisions := memory.NewDecisionStore()
	d, _ := agent.NewStepDecision("sess-1", "eng-1", agent.OutcomeExecuted, "act-1", "start_recon", "recon.subfinder", "app.acme.io", agent.RiskActive, "auto",
		agent.AgentReason{WhyTool: "enumerate"}, agent.AgentEvidenceRefs{StepHash: "h1"}, "agent:sess-1", now)
	if err := decisions.AppendDecision(ctx, d); err != nil {
		t.Fatal(err)
	}

	rt := &Router{log: logging.New("error")}
	rt.EnableAgent(nil, sessions, nil, nil, nil, 8, 256)
	rt.SetAgentDecisionStore(decisions)

	// In-scope engagement → 200 with the decision.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/engagements/eng-1/agent/sessions/sess-1/decisions", nil)
	req.SetPathValue("id", "eng-1")
	req.SetPathValue("sid", "sess-1")
	w := httptest.NewRecorder()
	rt.listAgentDecisions(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", w.Code)
	}
	var body struct {
		Decisions []agent.AgentDecision `json:"decisions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Decisions) != 1 || body.Decisions[0].Reason.WhyTool != "enumerate" || body.Decisions[0].Refs.StepHash != "h1" {
		t.Fatalf("unexpected decisions: %+v", body.Decisions)
	}

	// Wrong engagement → 404 (cross-engagement read blocked).
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/engagements/other/agent/sessions/sess-1/decisions", nil)
	req2.SetPathValue("id", "other")
	req2.SetPathValue("sid", "sess-1")
	w2 := httptest.NewRecorder()
	rt.listAgentDecisions(w2, req2)
	if w2.Code != http.StatusNotFound {
		t.Fatalf("cross-engagement read: status=%d, want 404", w2.Code)
	}
}
