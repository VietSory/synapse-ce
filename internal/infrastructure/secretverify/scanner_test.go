package secretverify

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeSecretScanner struct {
	report       ports.SecretScanReport
	history     ports.SecretScanReport
	scanCalls   int
	historyCalls int
}

func (s *fakeSecretScanner) Name() string { return "fake-secret-scan" }

func (s *fakeSecretScanner) ScanFiles(context.Context, string) (ports.SecretScanReport, error) {
	s.scanCalls++
	return s.report, nil
}

func (s *fakeSecretScanner) ScanHistory(context.Context, string) (ports.SecretScanReport, error) {
	s.historyCalls++
	return s.history, nil
}

type fakeSecretVerifier struct {
	results []ports.SecretVerification
	calls   int
}

func (v *fakeSecretVerifier) Verify(context.Context, string, []ports.SecretRawFinding) ([]ports.SecretVerification, error) {
	v.calls++
	return append([]ports.SecretVerification(nil), v.results...), nil
}

func TestScannerRequiresExplicitVerifiedLane(t *testing.T) {
	hit := ports.SecretRawFinding{File: "app.env", Line: 2, RuleID: "github-token"}
	base := &fakeSecretScanner{report: ports.SecretScanReport{Findings: []ports.SecretRawFinding{hit}}}
	verifier := &fakeSecretVerifier{results: []ports.SecretVerification{{
		File: "app.env", Line: 2, RuleID: "github-token", Status: ports.SecretVerificationVerified,
		Provider: "github", Reason: "credential_accepted",
	}}}
	wrapped, err := WrapScanner(base, verifier)
	if err != nil {
		t.Fatal(err)
	}

	report, err := wrapped.ScanFiles(context.Background(), ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || verifier.calls != 0 {
		t.Fatalf("plain scan findings=%d verifier calls=%d", len(report.Findings), verifier.calls)
	}

	report, results, err := wrapped.ScanFilesVerified(context.Background(), ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || verifier.calls != 1 || len(results) != 1 || results[0].Status != ports.SecretVerificationVerified {
		t.Fatalf("verified scan findings=%d verifier calls=%d results=%#v", len(report.Findings), verifier.calls, results)
	}
}

func TestScannerDropsMalformedVerificationMetadataButKeepsPresence(t *testing.T) {
	hit := ports.SecretRawFinding{File: "app.env", Line: 2, RuleID: "github-token"}
	base := &fakeSecretScanner{report: ports.SecretScanReport{Findings: []ports.SecretRawFinding{hit}}}
	verifier := &fakeSecretVerifier{results: []ports.SecretVerification{{
		File: "app.env", Line: 2, RuleID: "github-token", Status: ports.SecretVerificationVerified,
		Provider: "github\nforged", Reason: "credential_accepted",
	}}}
	wrapped, err := WrapScanner(base, verifier)
	if err != nil {
		t.Fatal(err)
	}

	report, results, err := wrapped.ScanFilesVerified(context.Background(), ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("presence finding was lost: %#v", report.Findings)
	}
	if len(results) != 0 {
		t.Fatalf("malformed verification crossed trust boundary: %#v", results)
	}
}

func TestScannerDelegatesHistoryWithoutActiveVerification(t *testing.T) {
	base := &fakeSecretScanner{history: ports.SecretScanReport{Findings: []ports.SecretRawFinding{{
		File: "old.env", Line: 1, RuleID: "github-token", FromHistory: true,
	}}}}
	verifier := &fakeSecretVerifier{}
	wrapped, err := WrapScanner(base, verifier)
	if err != nil {
		t.Fatal(err)
	}
	report, err := wrapped.ScanHistory(context.Background(), ".")
	if err != nil {
		t.Fatal(err)
	}
	if base.historyCalls != 1 || verifier.calls != 0 || len(report.Findings) != 1 {
		t.Fatalf("history calls=%d verifier calls=%d report=%#v", base.historyCalls, verifier.calls, report)
	}
}
