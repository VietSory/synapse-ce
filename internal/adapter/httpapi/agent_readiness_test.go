package httpapi

import (
	"testing"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
)

func TestBuildAgentReadinessRepoWorkflow(t *testing.T) {
	now := time.Date(2026, 6, 25, 10, 0, 0, 0, time.UTC)
	e, _ := engdom.New("eng-1", "", "repo", "client", now)
	from, to := now.Add(-time.Hour), now.Add(time.Hour)
	_ = e.SetAuthorizationWindow(&from, &to, "UTC", now)
	_ = e.SetScope([]engdom.Target{{Kind: engdom.TargetRepo, Value: "D:\\Mynavi\\vetcare"}}, nil, now)

	got := buildAgentReadiness(e, true, true, true, true, true, now)

	if got.Overall == "blocked" {
		t.Fatalf("repo analysis should not be globally blocked: %+v", got)
	}
	if !workflowReady(got.Workflows, "sca-reachability") {
		t.Fatalf("repo + sca + judgments should enable SCA reachability: %+v", got.Workflows)
	}
	if workflowReady(got.Workflows, "recon") {
		t.Fatalf("repo-only scope must not claim recon is ready: %+v", got.Workflows)
	}
	if len(got.SuggestedGoals) == 0 {
		t.Fatal("expected at least one suggested goal")
	}
}

func TestBuildAgentReadinessRuntimeReconRequiresLiveRecon(t *testing.T) {
	now := time.Date(2026, 6, 25, 10, 0, 0, 0, time.UTC)
	e, _ := engdom.New("eng-1", "", "web", "client", now)
	from, to := now.Add(-time.Hour), now.Add(time.Hour)
	_ = e.SetAuthorizationWindow(&from, &to, "UTC", now)
	_ = e.SetScope([]engdom.Target{{Kind: engdom.TargetURL, Value: "https://app.example.com"}}, nil, now)

	got := buildAgentReadiness(e, true, true, true, true, true, now)
	if workflowReady(got.Workflows, "recon") {
		t.Fatalf("live recon disabled should block recon readiness: %+v", got.Workflows)
	}
	if !workflowHasBlocker(got.Workflows, "recon", "live recon is disabled") {
		t.Fatalf("expected live recon blocker: %+v", got.Workflows)
	}

	e.SetLiveRecon(true, now)
	got = buildAgentReadiness(e, true, true, true, true, true, now)
	if !workflowReady(got.Workflows, "recon") {
		t.Fatalf("runtime scope + open window + live recon should enable recon: %+v", got.Workflows)
	}
	if !workflowReady(got.Workflows, "dast-planning") {
		t.Fatalf("URL scope + live recon should enable DAST planning: %+v", got.Workflows)
	}
}

func workflowReady(wfs []agentWorkflowReadiness, id string) bool {
	for _, wf := range wfs {
		if wf.ID == id {
			return wf.Ready
		}
	}
	return false
}

func workflowHasBlocker(wfs []agentWorkflowReadiness, id, blocker string) bool {
	for _, wf := range wfs {
		if wf.ID != id {
			continue
		}
		for _, b := range wf.Blockers {
			if b == blocker {
				return true
			}
		}
	}
	return false
}
