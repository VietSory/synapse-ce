package memory

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/hotspot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func projectionCandidate(key string, title string) hotspot.Candidate {
	return hotspot.Candidate{
		Key: key, FindingIdentity: key, RuleKey: "rule-" + key, Title: title, Description: "description",
		Severity: shared.SeverityHigh, Kind: finding.KindSAST,
	}
}

func projectionAnalysis(id string, at time.Time) projectanalysis.Analysis {
	return projectanalysis.Analysis{ID: id, TenantID: "tenant-a", ProjectID: "project-a", CreatedAt: at}
}

func TestProjectHotspotProjectionRescanPreservesReviewStateAndFirstSeen(t *testing.T) {
	ctx := context.Background()
	store := NewProjectAnalysisStore()
	firstAt := time.Date(2026, 7, 18, 1, 0, 0, 0, time.UTC)
	secondAt := firstAt.Add(time.Hour)
	first := projectionCandidate("sast:rule-a:main.go:1", "first")
	if err := store.SaveWithResultAndHotspots(ctx, projectionAnalysis("a1", firstAt), nil, []hotspot.Candidate{first}); err != nil {
		t.Fatal(err)
	}
	id := hotspot.DeterministicID("tenant-a", "project-a", first.Key)
	item, err := store.GetHotspot(ctx, "tenant-a", "project-a", id)
	if err != nil {
		t.Fatal(err)
	}
	item.Status, item.Version = hotspot.StatusSafe, 7
	store.hotspots[0] = item
	second := projectionCandidate(first.Key, "updated")
	second.Description = "updated description"
	if err := store.SaveWithResultAndHotspots(ctx, projectionAnalysis("a2", secondAt), nil, []hotspot.Candidate{second}); err != nil {
		t.Fatal(err)
	}
	older := projectionCandidate(first.Key, "older")
	olderAt := firstAt.Add(-time.Hour)
	if err := store.SaveWithResultAndHotspots(ctx, projectionAnalysis("a0", olderAt), nil, []hotspot.Candidate{older}); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetHotspot(ctx, "tenant-a", "project-a", id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != hotspot.StatusSafe || got.Version != 7 {
		t.Fatalf("review state reset: %+v", got)
	}
	if got.FirstSeenAnalysisID != "a0" || !got.FirstSeenAt.Equal(olderAt) || got.LastSeenAnalysisID != "a2" || !got.LastSeenAt.Equal(secondAt) || got.Title != "updated" {
		t.Fatalf("seen metadata/descriptive update: %+v", got)
	}
}

func TestProjectHotspotProjectionIsTenantAndProjectScoped(t *testing.T) {
	ctx := context.Background()
	store := NewProjectAnalysisStore()
	analysis := projectionAnalysis("a1", time.Unix(1, 0))
	if err := store.SaveWithResultAndHotspots(ctx, analysis, nil, []hotspot.Candidate{projectionCandidate("a", "title")}); err != nil {
		t.Fatal(err)
	}
	id := hotspot.DeterministicID("tenant-a", "project-a", "a")
	if _, err := store.GetHotspot(ctx, "tenant-b", "project-a", id); err != shared.ErrNotFound {
		t.Fatalf("cross-tenant get=%v, want not found", err)
	}
	if _, err := store.GetHotspot(ctx, "tenant-a", "project-b", id); err != shared.ErrNotFound {
		t.Fatalf("wrong-project get=%v, want not found", err)
	}
	page, err := store.ListHotspots(ctx, "tenant-b", "project-a", hotspot.ListFilter{})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("cross-tenant list=%+v err=%v", page, err)
	}
}

func TestProjectHotspotProjectionPaginationAndFacets(t *testing.T) {
	ctx := context.Background()
	store := NewProjectAnalysisStore()
	base := time.Date(2026, 7, 18, 1, 0, 0, 0, time.UTC)
	for i, key := range []string{"a", "b", "c"} {
		if err := store.SaveWithResultAndHotspots(ctx, projectionAnalysis("a"+key, base.Add(time.Duration(i)*time.Hour)), nil, []hotspot.Candidate{projectionCandidate(key, key)}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := store.ListHotspots(ctx, "tenant-a", "project-a", hotspot.ListFilter{Limit: 2})
	if err != nil || len(page.Items) != 2 || page.Next == nil || page.Facets.RuleKeys["rule-a"] != 1 {
		t.Fatalf("first page=%+v err=%v", page, err)
	}
	next, err := store.ListHotspots(ctx, "tenant-a", "project-a", hotspot.ListFilter{Limit: 2, BeforeLastSeenAt: page.Next.BeforeLastSeenAt, BeforeID: page.Next.BeforeID})
	if err != nil || len(next.Items) != 1 || next.Items[0].Key != "a" {
		t.Fatalf("next page=%+v err=%v", next, err)
	}
}

func TestProjectHotspotProjectionRejectsCandidateAtomically(t *testing.T) {
	ctx := context.Background()
	store := NewProjectAnalysisStore()
	valid := projectionCandidate("valid", "valid")
	invalid := valid
	invalid.Key = ""
	if err := store.SaveWithResultAndHotspots(ctx, projectionAnalysis("a1", time.Unix(1, 0)), nil, []hotspot.Candidate{valid, invalid}); err == nil {
		t.Fatal("invalid candidate should fail")
	}
	if _, _, err := store.List(ctx, "tenant-a", "project-a", 10, time.Time{}, ""); err != nil {
		t.Fatal(err)
	} else {
		analyses, _, _ := store.List(ctx, "tenant-a", "project-a", 10, time.Time{}, "")
		if len(analyses) != 0 {
			t.Fatalf("analysis committed despite projection validation: %+v", analyses)
		}
	}
	if page, err := store.ListHotspots(ctx, "tenant-a", "project-a", hotspot.ListFilter{}); err != nil || len(page.Items) != 0 {
		t.Fatalf("hotspot committed despite projection validation: %+v err=%v", page, err)
	}
}
