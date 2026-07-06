package report

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func sampleEngagement() *engagement.Engagement {
	return &engagement.Engagement{
		Name:   "acme-q3",
		Client: "Acme",
		Scope: engagement.Scope{
			InScope: []engagement.Target{{Kind: engagement.TargetRepo, Value: "/srv/app"}},
		},
	}
}

func sampleFindings() []finding.Finding {
	return []finding.Finding{
		{Title: "CVE-2020-7471 in django@2.2.0", Severity: shared.SeverityCritical, Status: finding.StatusConfirmed, RiskScore: 8.5, KEV: true},
		{Title: "Denied license: GPL-3.0-only", Severity: shared.SeverityHigh, Status: finding.StatusOpen},
	}
}

func TestRenderDeterministic(t *testing.T) {
	at := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	r := NewRenderer()
	a, err := r.Render(context.Background(), sampleEngagement(), sampleFindings(), ports.ReportInsight{HasScan: true, LicensePct: 92, LicenseDetected: 50, EvidenceIntact: true, EvidenceCount: 1, EvidenceHead: "abc123", ReproScore: 85}, at, "v1.2.3")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !bytes.HasPrefix(a, []byte("%PDF-")) {
		t.Fatalf("output is not a PDF: %q", a[:min(8, len(a))])
	}
	// Cross a wall-clock second so a leaking time.Now() (e.g. PDF /ModDate) would
	// diverge the bytes; the renderer must pin every date to the inputs.
	time.Sleep(1100 * time.Millisecond)
	b, err := r.Render(context.Background(), sampleEngagement(), sampleFindings(), ports.ReportInsight{HasScan: true, LicensePct: 92, LicenseDetected: 50, EvidenceIntact: true, EvidenceCount: 1, EvidenceHead: "abc123", ReproScore: 85}, at, "v1.2.3")
	if err != nil {
		t.Fatalf("render (second): %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("render is not byte-deterministic for identical inputs (%d vs %d bytes)", len(a), len(b))
	}
}

func TestRenderEmptyFindings(t *testing.T) {
	at := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	pdf, err := NewRenderer().Render(context.Background(), &engagement.Engagement{Name: "empty"}, nil, ports.ReportInsight{}, at, "v1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF-")) {
		t.Fatal("output is not a PDF")
	}
}
