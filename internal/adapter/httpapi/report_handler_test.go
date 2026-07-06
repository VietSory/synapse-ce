package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	infrareport "github.com/KKloudTarus/synapse-ce/internal/infrastructure/report"
	reportuc "github.com/KKloudTarus/synapse-ce/internal/usecase/report"
)

func newReportRouter() *Router {
	clock := fixedClock{t: time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)}
	engRepo := newEngRepoFake()
	_ = engRepo.Create(context.Background(), &engdom.Engagement{ID: shared.ID("e1"), Name: "acme-q3", Client: "Acme", Status: engdom.StatusActive})
	findRepo := newFindRepoFake()
	_ = findRepo.Upsert(context.Background(), []finding.Finding{
		{ID: "manual:1", EngagementID: "e1", Title: "Stored XSS <script>", Severity: shared.SeverityHigh, Status: finding.StatusConfirmed, CWE: "CWE-79", Priority: 4, Description: "payload"},
		{ID: "sca:1", EngagementID: "e1", Title: "Old lib", Severity: shared.SeverityMedium, Status: finding.StatusOpen, Priority: 2},
	})
	svc := reportuc.NewService(engRepo, findRepo, nil, nil, infrareport.NewRenderer(), nil, clock, "vtest")
	svc.RegisterFormat(reportuc.FormatHTML, infrareport.NewHTMLRenderer())
	svc.RegisterFormat(reportuc.FormatDOCX, infrareport.NewDOCXRenderer())
	return &Router{log: discardLog(), report: svc}
}

func reportReq(path string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.SetPathValue("id", "e1")
	return req
}

func TestExportReportHTML(t *testing.T) {
	rt := newReportRouter()
	rec := httptest.NewRecorder()
	rt.exportReportHTML(rec, reportReq("/api/v1/engagements/e1/report.html"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q", ct)
	}
	if rec.Header().Get("X-Report-SHA256") == "" {
		t.Error("missing X-Report-SHA256 seal header")
	}
	body := rec.Body.String()
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("finding title was not HTML-escaped in the report")
	}
	for _, want := range []string{"acme-q3", "Findings Overview", "Old lib", "Stored XSS"} {
		if !strings.Contains(body, want) {
			t.Errorf("report missing %q", want)
		}
	}
}

func TestExportReportHTMLStatusAndSectionFilter(t *testing.T) {
	rt := newReportRouter()
	rec := httptest.NewRecorder()
	rt.exportReportHTML(rec, reportReq("/api/v1/engagements/e1/report.html?status=confirmed&section=findings"))

	body := rec.Body.String()
	if !strings.Contains(body, "Stored XSS") {
		t.Error("confirmed finding should be present")
	}
	if strings.Contains(body, "Old lib") {
		t.Error("open finding should be filtered out by status=confirmed")
	}
	if strings.Contains(body, "Executive Summary") {
		t.Error("section=findings should exclude the summary section")
	}
}

func TestExportReportDOCXIsValidPackage(t *testing.T) {
	rt := newReportRouter()
	rec := httptest.NewRecorder()
	rt.exportReportDOCX(rec, reportReq("/api/v1/engagements/e1/report.docx?title=Q3+Assessment"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "wordprocessingml") {
		t.Errorf("content-type = %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, ".docx") {
		t.Errorf("content-disposition = %q", cd)
	}
	b := rec.Body.Bytes()
	if _, err := zip.NewReader(bytes.NewReader(b), int64(len(b))); err != nil {
		t.Fatalf("response is not a valid .docx (zip): %v", err)
	}
}

func TestListWriteupsEndpoint(t *testing.T) {
	rt := &Router{log: discardLog()}
	rec := httptest.NewRecorder()
	rt.listWriteups(rec, httptest.NewRequest(http.MethodGet, "/api/v1/writeups", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var got []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("writeup catalog is empty")
	}
	found := false
	for _, w := range got {
		if w["id"] == "sqli" {
			found = true
		}
	}
	if !found {
		t.Error("expected the sqli writeup in the catalog")
	}
}
