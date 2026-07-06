package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	dastverifieruc "github.com/KKloudTarus/synapse-ce/internal/usecase/dastverifier"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
)

type recordingRuntimeVerifier struct {
	engID shared.ID
	res   dastverifieruc.Result
}

func (r *recordingRuntimeVerifier) Apply(_ context.Context, engagementID shared.ID, res dastverifieruc.Result) (judgment.Judgment, error) {
	r.engID = engagementID
	r.res = res
	return judgment.Judgment{ID: res.JudgmentID, EngagementID: engagementID, Capability: judgment.CapSAST, State: judgment.StateConfirmed, EvidenceScore: res.Score}, nil
}

func TestRuntimeVerificationRoutePassesTypedProofResult(t *testing.T) {
	engRepo := memory.NewEngagementRepository()
	if err := engRepo.Create(context.Background(), &engdom.Engagement{
		ID: "engA", TenantID: "tenantA", Name: "A", Client: "A", Status: engdom.StatusActive,
	}); err != nil {
		t.Fatalf("seed engagement: %v", err)
	}
	rv := &recordingRuntimeVerifier{}
	rt := &Router{
		log: discardLog(),
		eng: enguc.NewService(engRepo, fixedClock{}, engIDs{}, &fakeAudit{}),
	}
	rt.SetRuntimeVerifier(rv)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/engA/judgments/j1/runtime-verification",
		bytes.NewBufferString(`{"score":85,"proof_class":"runtime_confirmed","rationale":"safe canary observed","version":3}`))
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "reviewer-1", Role: "reviewer", TenantID: "tenantA"}))
	rec := httptest.NewRecorder()
	rt.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("runtime verifier route status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rv.engID != "engA" || rv.res.JudgmentID != "j1" || rv.res.Verifier != "reviewer-1" || rv.res.Score != 85 ||
		rv.res.ProofClass != dastverifieruc.ProofClassRuntimeConfirmed || rv.res.Rationale != "safe canary observed" || rv.res.ExpectedVersion != 3 {
		t.Fatalf("runtime verifier route lost typed result fields: eng=%q res=%+v", rv.engID, rv.res)
	}
}
