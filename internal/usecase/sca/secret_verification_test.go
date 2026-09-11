package sca

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func secretVerificationFixture() (ports.SecretRawFinding, finding.Finding) {
	raw := ports.SecretRawFinding{
		File: "config/app.env", Line: 7, RuleID: "github-token", Category: "GitHub",
		Title: "GitHub token", Match: "ghp_****REDACTED",
	}
	item := finding.Finding{
		Title:       "GitHub token (config/app.env:7)",
		Description: "A redacted secret was detected.",
		Kind:        finding.KindSecret,
		DedupKey:    secretDedupKey(raw),
		Sources:     []string{"synapse-secret-scan"},
		Confidence:  vulnerability.ConfidenceMedium,
	}
	return raw, item
}

func TestApplySecretVerificationVerifiedRaisesAboveNeedsVerify(t *testing.T) {
	raw, item := secretVerificationFixture()
	result := &ScanResult{
		Findings: []finding.Finding{item},
		NeedsVerification: []NeedsVerifyFinding{{DedupKey: item.DedupKey, Title: item.Title, Reason: "pending"}},
	}
	verification := ports.SecretVerification{
		File: raw.File, Line: raw.Line, RuleID: raw.RuleID,
		Status: ports.SecretVerificationVerified, Provider: "github", Reason: "credential_accepted",
	}

	applySecretVerification(result, []ports.SecretRawFinding{raw}, []ports.SecretVerification{verification})
	applySecretVerification(result, []ports.SecretRawFinding{raw}, []ports.SecretVerification{verification})

	if len(result.Findings) != 1 {
		t.Fatalf("presence finding count = %d, want 1", len(result.Findings))
	}
	if len(result.NeedsVerification) != 0 {
		t.Fatalf("verified credential remained in needs-verify: %#v", result.NeedsVerification)
	}
	got := result.Findings[0]
	if got.Confidence != vulnerability.ConfidenceHigh {
		t.Fatalf("confidence = %q, want high", got.Confidence)
	}
	if countString(got.Sources, secretVerificationSourcePrefix+"github") != 1 {
		t.Fatalf("sources = %#v", got.Sources)
	}
	if !strings.Contains(got.Description, "credential accepted by github") {
		t.Fatalf("description missing active verification: %q", got.Description)
	}
	if strings.Contains(got.Description, "ghp_") || strings.Contains(strings.Join(got.Sources, " "), "ghp_") {
		t.Fatal("raw/redacted credential material leaked into verification projection")
	}
}

func TestApplySecretVerificationUnverifiedRetainsAndQueues(t *testing.T) {
	raw, item := secretVerificationFixture()
	result := &ScanResult{Findings: []finding.Finding{item}}
	applySecretVerification(result, []ports.SecretRawFinding{raw}, []ports.SecretVerification{{
		File: raw.File, Line: raw.Line, RuleID: raw.RuleID,
		Status: ports.SecretVerificationUnverified, Provider: "github", Reason: "credential_rejected",
	}})
	if len(result.Findings) != 1 {
		t.Fatal("unverified credential presence finding was removed")
	}
	if len(result.NeedsVerification) != 1 || result.NeedsVerification[0].DedupKey != item.DedupKey {
		t.Fatalf("needs-verify = %#v", result.NeedsVerification)
	}
	if !strings.Contains(result.Findings[0].Description, "credential rejected by github") {
		t.Fatalf("description = %q", result.Findings[0].Description)
	}
}

func TestApplySecretVerificationUnknownRetainsAndQueues(t *testing.T) {
	raw, item := secretVerificationFixture()
	result := &ScanResult{Findings: []finding.Finding{item}}
	applySecretVerification(result, []ports.SecretRawFinding{raw}, []ports.SecretVerification{{
		File: raw.File, Line: raw.Line, RuleID: raw.RuleID,
		Status: ports.SecretVerificationUnknown, Provider: "github", Reason: "provider_unavailable",
	}})
	if len(result.Findings) != 1 || len(result.NeedsVerification) != 1 {
		t.Fatalf("finding/queue = %d/%d", len(result.Findings), len(result.NeedsVerification))
	}
	if result.Findings[0].Confidence != vulnerability.ConfidenceMedium {
		t.Fatalf("unknown status changed detector confidence to %q", result.Findings[0].Confidence)
	}
}

func TestApplySecretVerificationRejectsForgedOrSuppressedEvidence(t *testing.T) {
	raw, item := secretVerificationFixture()
	result := &ScanResult{Findings: []finding.Finding{item}}
	applySecretVerification(result, []ports.SecretRawFinding{raw}, []ports.SecretVerification{{
		File: raw.File, Line: raw.Line, RuleID: raw.RuleID,
		Status: ports.SecretVerificationVerified, Provider: "github\nforged", Reason: "credential_accepted",
	}, {
		File: "other.env", Line: 99, RuleID: "github-token",
		Status: ports.SecretVerificationVerified, Provider: "github", Reason: "credential_accepted",
	}})
	if len(result.NeedsVerification) != 0 {
		t.Fatalf("forged evidence changed queue: %#v", result.NeedsVerification)
	}
	if len(result.Findings[0].Sources) != 1 || result.Findings[0].Confidence != vulnerability.ConfidenceMedium {
		t.Fatalf("forged evidence changed finding: %#v", result.Findings[0])
	}
}

func TestApplySecretVerificationDoesNotVerifyHistory(t *testing.T) {
	raw, item := secretVerificationFixture()
	raw.FromHistory = true
	raw.Commit = "abc123"
	result := &ScanResult{Findings: []finding.Finding{item}}
	applySecretVerification(result, []ports.SecretRawFinding{raw}, []ports.SecretVerification{{
		File: raw.File, Line: raw.Line, RuleID: raw.RuleID,
		Status: ports.SecretVerificationVerified, Provider: "github", Reason: "credential_accepted",
	}})
	if len(result.Findings[0].Sources) != 1 || result.Findings[0].Confidence != vulnerability.ConfidenceMedium {
		t.Fatalf("history credential was actively verified: %#v", result.Findings[0])
	}
}

func countString(values []string, target string) int {
	n := 0
	for _, value := range values {
		if value == target {
			n++
		}
	}
	return n
}
