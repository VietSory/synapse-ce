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

// TestGetAgentPlan_EngagementScoped: the plan endpoint returns the session's DAG, scoped to its
// engagement (a mismatched engagement id is 404), and an empty object when there is no plan.
func TestGetAgentPlan_EngagementScoped(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_000, 0).UTC()
	sessions := memory.NewAgentSessionStore()
	sess, err := agent.NewSession("sess-1", "eng-1", "alice", "goal", "m", "", "", now, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := sessions.SaveSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	plans := memory.NewPlanStore()
	plan, err := agent.NewPlan("plan-1", "sess-1", "eng-1", "goal",
		[]agent.PlanNode{{ID: "a", Tool: "subfinder", Target: "app.acme.io", ActionID: "act-a", Risk: agent.RiskActive}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := plans.CreatePlan(ctx, plan); err != nil {
		t.Fatal(err)
	}

	rt := &Router{log: logging.New("error")}
	rt.EnableAgent(nil, sessions, nil, nil, nil, 8, 256)
	rt.SetAgentPlanStore(plans)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/engagements/eng-1/agent/sessions/sess-1/plan", nil)
	req.SetPathValue("id", "eng-1")
	req.SetPathValue("sid", "sess-1")
	w := httptest.NewRecorder()
	rt.getAgentPlan(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", w.Code)
	}
	var body struct {
		Plan *agent.Plan `json:"plan"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Plan == nil || len(body.Plan.Nodes) != 1 || body.Plan.Nodes[0].Tool != "subfinder" {
		t.Fatalf("unexpected plan: %+v", body.Plan)
	}

	// Cross-engagement → 404.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/engagements/other/agent/sessions/sess-1/plan", nil)
	req2.SetPathValue("id", "other")
	req2.SetPathValue("sid", "sess-1")
	w2 := httptest.NewRecorder()
	rt.getAgentPlan(w2, req2)
	if w2.Code != http.StatusNotFound {
		t.Fatalf("cross-engagement: status=%d, want 404", w2.Code)
	}
}
