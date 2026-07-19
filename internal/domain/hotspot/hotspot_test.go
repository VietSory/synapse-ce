package hotspot

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestHotspotValidateAndDeterministicID(t *testing.T) {
	now := time.Date(2026, 7, 19, 1, 2, 3, 0, time.UTC)
	h := Hotspot{
		ID: "id", TenantID: "tenant", ProjectID: "project", Key: "sast:rule:file:1", FindingIdentity: "sast:rule:file:1",
		RuleKey: "rule", Title: "Title", Description: "Description", Severity: shared.SeverityHigh,
		Kind: finding.KindSAST, Status: StatusToReview, Version: 1, FirstSeenAnalysisID: "a1", LastSeenAnalysisID: "a1",
		FirstSeenAt: now, LastSeenAt: now,
	}
	if err := h.Validate(); err != nil {
		t.Fatal(err)
	}
	if got, want := DeterministicID("tenant", "project", h.Key), DeterministicID("tenant", "project", h.Key); got != want || got.IsZero() {
		t.Fatalf("deterministic id=%q want=%q", got, want)
	}
	if DeterministicID("other", "project", h.Key) == DeterministicID("tenant", "project", h.Key) {
		t.Fatal("tenant must be part of deterministic identity")
	}
}

func TestHotspotValidateAllowsDefaultTenant(t *testing.T) {
	now := time.Date(2026, 7, 19, 1, 2, 3, 0, time.UTC)
	h := Hotspot{
		ID: "id", ProjectID: "project", Key: "sast:rule:file:1", FindingIdentity: "sast:rule:file:1",
		RuleKey: "rule", Severity: shared.SeverityUnknown,
		Status: StatusToReview, Version: 1, FirstSeenAnalysisID: "a1", LastSeenAnalysisID: "a1",
		FirstSeenAt: now, LastSeenAt: now,
	}
	if err := h.Validate(); err != nil {
		t.Fatalf("default tenant should be valid: %v", err)
	}
}

func TestStatusValid(t *testing.T) {
	for _, status := range []Status{StatusToReview, StatusAcknowledged, StatusFixed, StatusSafe} {
		if !status.Valid() {
			t.Errorf("%q should be valid", status)
		}
	}
	if Status("unknown").Valid() {
		t.Fatal("unknown status should be invalid")
	}
}
