package memory

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestFindingRepositoryUpsertDedup(t *testing.T) {
	r := NewFindingRepository()
	ctx := context.Background()

	f := finding.Finding{ID: "f1", EngagementID: "e1", Title: "v1", Severity: shared.SeverityHigh, Status: finding.StatusOpen, DedupKey: "vuln:CVE-1"}
	if err := r.Upsert(ctx, []finding.Finding{f}); err != nil {
		t.Fatal(err)
	}

	// re-upsert the same dedup with a higher severity and a different status:
	// dedup → one row; severity updates; triage status is preserved (stays open).
	f2 := f
	f2.Severity = shared.SeverityCritical
	f2.Status = finding.StatusConfirmed
	if err := r.Upsert(ctx, []finding.Finding{f2}); err != nil {
		t.Fatal(err)
	}

	list, err := r.ListByEngagement(ctx, "e1")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("want 1 deduped finding, got %d", len(list))
	}
	if list[0].Severity != shared.SeverityCritical {
		t.Errorf("severity should update to critical, got %v", list[0].Severity)
	}
	if list[0].Status != finding.StatusOpen {
		t.Errorf("triage status should be preserved as open, got %v", list[0].Status)
	}

	// other engagements isolated
	if l, _ := r.ListByEngagement(ctx, "other"); len(l) != 0 {
		t.Errorf("other engagement should have no findings, got %d", len(l))
	}
}
