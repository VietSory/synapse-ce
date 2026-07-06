package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastrunner"
	dastworkflowuc "github.com/KKloudTarus/synapse-ce/internal/usecase/dastworkflow"
)

type recordingDASTWorkflow struct {
	proposed dastrunner.Probe
	decideID shared.ID
	runID    shared.ID
	runProbe dastrunner.Probe
}

func (r *recordingDASTWorkflow) Propose(_ context.Context, _ string, _ shared.ID, p dastrunner.Probe) (dastworkflowuc.Proposal, error) {
	r.proposed = p
	return dastworkflowuc.Proposal{Decision: agent.ApprovalDecision{State: agent.ApprovalPending}}, nil
}
func (r *recordingDASTWorkflow) Decide(_ context.Context, _ string, _ shared.ID, actionID shared.ID, approve bool, _ string) (agent.ApprovalDecision, error) {
	r.decideID = actionID
	state := agent.ApprovalDenied
	if approve {
		state = agent.ApprovalApproved
	}
	return agent.ApprovalDecision{ActionID: actionID, State: state}, nil
}
func (r *recordingDASTWorkflow) Run(_ context.Context, _ string, _ shared.ID, actionID shared.ID, p dastrunner.Probe) (dastrunner.Result, error) {
	r.runID = actionID
	r.runProbe = p
	return dastrunner.Result{Proof: "runtime_confirmed", Status: http.StatusOK}, nil
}

func TestDASTWorkflowHandlersPassTypedProbe(t *testing.T) {
	wf := &recordingDASTWorkflow{}
	rt := &Router{log: discardLog()}
	rt.SetDASTWorkflow(wf)
	body := `{"url":"https://app.acme.test/search?q=synapse-canary","method":"GET","expected_status":200,"expected_body_contains":"synapse-canary","score_if_confirmed":85,"score_if_refuted":30,"version":7,"rationale":"safe canary"}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/eng-1/judgments/j-1/runtime-verification/proposals", strings.NewReader(body))
	req.SetPathValue("id", "eng-1")
	req.SetPathValue("jid", "j-1")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", Role: "consultant"}))
	rec := httptest.NewRecorder()
	rt.proposeRuntimeVerification(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("propose status=%d body=%s", rec.Code, rec.Body.String())
	}
	if wf.proposed.JudgmentID != "j-1" || wf.proposed.ScoreIfConfirmed != 85 || wf.proposed.ExpectedVersion != 7 {
		t.Fatalf("proposal probe not mapped correctly: %+v", wf.proposed)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/engagements/eng-1/dast/approvals/a-1/decide", strings.NewReader(`{"approve":true,"reason":"ok"}`))
	req.SetPathValue("id", "eng-1")
	req.SetPathValue("aid", "a-1")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "bob", Role: "reviewer"}))
	rec = httptest.NewRecorder()
	rt.decideRuntimeVerification(rec, req)
	if rec.Code != http.StatusOK || wf.decideID != "a-1" {
		t.Fatalf("decide status=%d id=%s body=%s", rec.Code, wf.decideID, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/engagements/eng-1/judgments/j-1/runtime-verification/proposals/a-1/run", strings.NewReader(body))
	req.SetPathValue("id", "eng-1")
	req.SetPathValue("jid", "j-1")
	req.SetPathValue("aid", "a-1")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", Role: "consultant"}))
	rec = httptest.NewRecorder()
	rt.runRuntimeVerification(rec, req)
	if rec.Code != http.StatusOK || wf.runID != "a-1" || wf.runProbe.JudgmentID != "j-1" {
		t.Fatalf("run status=%d id=%s probe=%+v body=%s", rec.Code, wf.runID, wf.runProbe, rec.Body.String())
	}
}
