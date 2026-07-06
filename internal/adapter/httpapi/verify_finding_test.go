package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/platform/logging"
)

// fakeVerifier records the Confirm call (the distinct-verifier verdict).
type fakeVerifier struct {
	verifier string
	score    int
	called   bool
}

func (f *fakeVerifier) Confirm(_ context.Context, verifier string, _, _ shared.ID, score int, _ string, _ int) (finding.Finding, error) {
	f.called = true
	f.verifier, f.score = verifier, score
	return finding.Finding{ID: "find-1", Kind: finding.KindExploitation, EvidenceScore: score}, nil
}

func TestVerifyFinding_MachineRoleForbidden(t *testing.T) {
	fv := &fakeVerifier{}
	rt := &Router{log: logging.New("error")}
	rt.SetExploitation(fv)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/e1/findings/f1/verify", strings.NewReader(`{"score":90,"version":1}`))
	req = withPrincipal(req, "mcp-bot", "mcp") // a machine role
	req.SetPathValue("id", "e1")
	req.SetPathValue("fid", "f1")
	w := httptest.NewRecorder()
	rt.authz(userdom.PermReview, rt.verifyFinding)(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a machine role must be 403, got %d", w.Code)
	}
	if fv.called {
		t.Fatal("Confirm must NOT be called for a machine principal")
	}
}

func TestVerifyFinding_HumanVerifierConfirms(t *testing.T) {
	fv := &fakeVerifier{}
	rt := &Router{log: logging.New("error")}
	rt.SetExploitation(fv)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/e1/findings/f1/verify", strings.NewReader(`{"score":90,"rationale":"reproduced","version":2}`))
	req = withPrincipal(req, "alice", "reviewer") // reviewer holds PermReview (sign-off)
	req.SetPathValue("id", "e1")
	req.SetPathValue("fid", "f1")
	w := httptest.NewRecorder()
	rt.authz(userdom.PermReview, rt.verifyFinding)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", w.Code)
	}
	if !fv.called || fv.verifier != "alice" || fv.score != 90 {
		t.Fatalf("Confirm not called with the human verifier: called=%v verifier=%q score=%d", fv.called, fv.verifier, fv.score)
	}
}
