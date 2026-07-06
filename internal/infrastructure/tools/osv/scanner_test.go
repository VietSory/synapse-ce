package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

func TestDedupRawsKeepsRichest(t *testing.T) {
	in := []vulnerability.RawFinding{
		{AdvisoryID: "CVE-1", Component: "django", Version: "2.2.0", Severity: shared.SeverityUnknown},
		{AdvisoryID: "CVE-1", Component: "django", Version: "2.2.0", Severity: shared.SeverityHigh, FixedVersion: "3.0"},
		{AdvisoryID: "CVE-2", Component: "django", Version: "2.2.0", Severity: shared.SeverityLow},
	}
	out := dedupRaws(in)
	if len(out) != 2 {
		t.Fatalf("want 2 deduped raws, got %d: %+v", len(out), out)
	}
	for _, v := range out {
		if v.AdvisoryID == "CVE-1" && (v.Severity != shared.SeverityHigh || v.FixedVersion != "3.0") {
			t.Errorf("CVE-1 kept %q/%q, want high/3.0 (richest record)", v.Severity, v.FixedVersion)
		}
	}
}

func TestOsvToRaw(t *testing.T) {
	comp := sbom.Component{Name: "foo", Version: "1.2.3", PURL: "pkg:golang/foo@1.2.3"}
	v := osvVuln{
		ID:               "GHSA-xxxx-yyyy-zzzz",
		Summary:          "bad thing",
		Aliases:          []string{"CVE-2024-9999"},
		Severity:         []osvSeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
		Affected:         []osvAffected{{Ranges: []osvRange{{Events: []map[string]string{{"introduced": "0"}, {"fixed": "1.2.4"}}}}}},
		DatabaseSpecific: map[string]any{"severity": "HIGH"},
	}
	got := osvToRaw(comp, v)
	if got.AdvisoryID != "CVE-2024-9999" {
		t.Errorf("AdvisoryID = %q, want the CVE alias", got.AdvisoryID)
	}
	if got.Source != "osv" {
		t.Errorf("Source = %q, want osv (the detector)", got.Source)
	}
	if got.Severity != shared.SeverityHigh {
		t.Errorf("Severity = %q, want high", got.Severity)
	}
	if got.CVSSVector == "" {
		t.Error("CVSSVector empty, want the CVSS_V3 vector")
	}
	if got.CVSSScore < 9.7 || got.CVSSScore > 9.9 {
		t.Errorf("CVSSScore = %.2f, want ~9.8 (computed from the vector)", got.CVSSScore)
	}
	if got.FixedVersion != "1.2.4" {
		t.Errorf("FixedVersion = %q, want 1.2.4", got.FixedVersion)
	}
	if got.Component != "foo" || got.Version != "1.2.3" {
		t.Errorf("component/version = %q/%q", got.Component, got.Version)
	}
}

func TestOsvToRawAffectedSymbols(t *testing.T) {
	// the Go vuln DB carries affected functions in affected[].ecosystem_specific.imports[].symbols
	const raw = `{"id":"GO-2024-1","aliases":["CVE-2024-1"],
		"affected":[{"ecosystem_specific":{"imports":[{"path":"github.com/foo/bar","symbols":["Vuln","Other"]}]}}]}`
	var v osvVuln
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatal(err)
	}
	got := osvToRaw(sbom.Component{Name: "bar", Version: "1.0.0"}, v)
	if len(got.AffectedSymbols) != 2 || got.AffectedSymbols[0] != "github.com/foo/bar.Vuln" || got.AffectedSymbols[1] != "github.com/foo/bar.Other" {
		t.Fatalf("AffectedSymbols = %v, want path-qualified [Vuln Other]", got.AffectedSymbols)
	}
}

func TestScanAgainstFakeOSV(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(batchResp{Results: []batchResult{
			{Vulns: []batchVuln{{ID: "GHSA-aaaa-bbbb-cccc"}}}, // component 0: one vuln
			{}, // component 1: none
		}})
	})
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(osvVuln{
			ID:               r.PathValue("id"),
			Summary:          "vulnerable",
			Severity:         []osvSeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			Affected:         []osvAffected{{Ranges: []osvRange{{Events: []map[string]string{{"fixed": "2.0.0"}}}}}},
			DatabaseSpecific: map[string]any{"severity": "CRITICAL"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sc := New(srv.URL, srv.Client())
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "vuln-pkg", Version: "1.0.0", PURL: "pkg:npm/vuln-pkg@1.0.0"},
		{Name: "clean-pkg", Version: "1.0.0", PURL: "pkg:npm/clean-pkg@1.0.0"},
	}}

	vulns, err := sc.Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("want 1 vuln, got %d: %+v", len(vulns), vulns)
	}
	got := vulns[0]
	if got.AdvisoryID != "GHSA-aaaa-bbbb-cccc" || got.Component != "vuln-pkg" {
		t.Errorf("vuln = %+v", got)
	}
	if got.Severity != shared.SeverityCritical || got.FixedVersion != "2.0.0" {
		t.Errorf("severity/fixed = %q/%q", got.Severity, got.FixedVersion)
	}
}

func TestScanEmptySBOM(t *testing.T) {
	sc := New("http://unused.invalid", http.DefaultClient)
	v, err := sc.Scan(context.Background(), &sbom.SBOM{})
	if err != nil || v != nil {
		t.Fatalf("empty sbom: v=%v err=%v (want nil,nil, no network call)", v, err)
	}
}
