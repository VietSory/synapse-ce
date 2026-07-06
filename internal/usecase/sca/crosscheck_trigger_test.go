package sca

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// fakeVulnFinds is a detection source that reports one vuln (so it can DISAGREE with the silent fakeVuln).
type fakeVulnFinds struct{}

func (fakeVulnFinds) Name() string { return "owned" }
func (fakeVulnFinds) Scan(context.Context, *sbom.SBOM) ([]vulnerability.RawFinding, error) {
	return []vulnerability.RawFinding{{Source: "owned", AdvisoryID: "CVE-1", Component: "pkg", Version: "1.0", Severity: shared.SeverityHigh}}, nil
}

type fakeCorrelation struct {
	called bool
	report vulnerability.CrossCheckReport
}

func (f *fakeCorrelation) Record(_ context.Context, _ shared.ID, r vulnerability.CrossCheckReport) (int, error) {
	f.called = true
	f.report = r
	return len(r.Disagreements), nil
}

var _ ports.CorrelationRecorder = (*fakeCorrelation)(nil)

// TestScanCrossCheckTrigger: when the run detection sources disagree on a vuln, the post-scan cross-check
// trigger feeds CrossCheck the run-source NAMES + the raws and calls the recorder with the disagreement.
func TestScanCrossCheckTrigger(t *testing.T) {
	repo := &fakeEngRepo{eng: engagementWithScope(t, "myrepo")}
	svc := NewService(repo, nil, nil, nil, nil, nil, nil, nil, ports.Provenance{}, fakeClock{t: time.Unix(0, 0).UTC()},
		&fakeAudit{}, shared.SeverityHigh, 0, &fakeAcquirer{dir: "/tmp/ws"}, &fakeDetector{}, fakeSBOM{},
		[]ports.DetectionSource{fakeVulnFinds{}, fakeVuln{}}, nil, fakeLic{}, nil) // "owned" reports CVE-1; "fake" reports nothing
	cc := &fakeCorrelation{}
	svc.SetCorrelation(cc)

	if _, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !cc.called {
		t.Fatal("the cross-check recorder must be called when run sources disagree")
	}
	if len(cc.report.Disagreements) != 1 || cc.report.Disagreements[0].AdvisoryID != "CVE-1" {
		t.Fatalf("want 1 disagreement on CVE-1, got %+v", cc.report.Disagreements)
	}
	if got := cc.report.Disagreements[0].Missing; len(got) != 1 || got[0] != "fake" {
		t.Errorf("the silent source 'fake' must be recorded as Missing, got %v", got)
	}
}

// TestScanNoCrossCheckRecorder: with no recorder set (default), the scan runs normally and nothing is minted.
func TestScanNoCrossCheckRecorder(t *testing.T) {
	repo := &fakeEngRepo{eng: engagementWithScope(t, "myrepo")}
	svc := newSvc(repo, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: "/tmp/ws"}, &fakeAudit{}, &fakeDetector{})
	if _, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"}); err != nil {
		t.Fatalf("Scan without a cross-check recorder must still succeed: %v", err)
	}
}
