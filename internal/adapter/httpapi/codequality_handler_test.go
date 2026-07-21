package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/codequality"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

type scanResultsFake struct {
	data []byte
	err  error
}

func (s scanResultsFake) SaveResult(context.Context, shared.ID, []byte) error { return nil }
func (s scanResultsFake) LatestResult(context.Context, shared.ID) ([]byte, error) {
	return s.data, s.err
}

func newCodeQualityRouter(t *testing.T, results ports.ScanResultStore) *Router {
	t.Helper()
	rt, _, _ := newEngRouter(t)
	rt.sca = scauc.NewService(nil, nil, nil, results, nil, nil, nil, nil, ports.Provenance{}, fixedClock{}, &fakeAudit{}, shared.SeverityInfo, 0, nil, nil, nil, nil, nil, nil, nil)
	return rt
}

func codeQualityCall(rt *Router) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/engagements/eng-1/code-quality", nil)
	req.SetPathValue("id", "eng-1")
	rec := httptest.NewRecorder()
	rt.codeQualityReport(rec, req)
	return rec
}

func TestCodeQualityReportReturnsStoredScanResult(t *testing.T) {
	stored := codequality.Report{Findings: []finding.Finding{{Title: "Stored finding"}}}
	data, err := json.Marshal(struct {
		CodeQuality *codequality.Report `json:"code_quality"`
	}{CodeQuality: &stored})
	if err != nil {
		t.Fatal(err)
	}
	rec := codeQualityCall(newCodeQualityRouter(t, scanResultsFake{data: data}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got codeQualityReportView
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Available || got.Report == nil || len(got.Report.Findings) != 1 || got.Report.Findings[0].Title != "Stored finding" {
		t.Fatalf("response = %+v", got)
	}
}

func TestCodeQualityReportWithoutStoredReportIsUnavailable(t *testing.T) {
	rec := codeQualityCall(newCodeQualityRouter(t, scanResultsFake{data: []byte(`{}`)}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got codeQualityReportView
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Available || got.Reason != codeQualityUnavailable {
		t.Fatalf("response = %+v", got)
	}
}

func TestCodeQualityReportWithoutScanIsUnavailable(t *testing.T) {
	rec := codeQualityCall(newCodeQualityRouter(t, scanResultsFake{err: shared.ErrNotFound}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got codeQualityReportView
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Available || got.Reason != codeQualityUnavailable {
		t.Fatalf("response = %+v", got)
	}
}

func TestCodeQualityReportRejectsInvalidStoredResult(t *testing.T) {
	rec := codeQualityCall(newCodeQualityRouter(t, scanResultsFake{data: []byte("not json")}))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestCodeQualityReportSurfacesResultStoreError(t *testing.T) {
	rec := codeQualityCall(newCodeQualityRouter(t, scanResultsFake{err: errors.New("store unavailable")}))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}
