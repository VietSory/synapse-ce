package projectuc

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

func TestGetMeasures(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	analyses := memory.NewProjectAnalysisStore()

	svc := NewService(projects, memory.NewEngagementRepository(), fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(analyses)

	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if err != nil {
		t.Fatal(err)
	}

	analysis := projectanalysis.Analysis{
		ID:        "a1",
		TenantID:  "tenant",
		ProjectID: string(p.ID),
		CreatedAt: time.Now(),
		Snapshot: measure.Snapshot{
			Nodes: []measure.Node{
				{Path: "", Kind: measure.NodeProject, Parent: ""},
				{Path: "src", Kind: measure.NodeDirectory, Parent: ""},
				{Path: "src/main.go", Kind: measure.NodeFile, Parent: "src"},
			},
		},
	}
	if err := analyses.Save(ctx, analysis); err != nil {
		t.Fatal(err)
	}

	t.Run("root", func(t *testing.T) {
		res, err := svc.GetMeasures(ctx, "tenant", "project", "")
		if err != nil {
			t.Fatal(err)
		}
		if res.Component.Path != "" || len(res.Children) != 1 || res.Children[0].Path != "src" {
			t.Fatalf("root response=%+v", res)
		}
	})

	t.Run("directory", func(t *testing.T) {
		res, err := svc.GetMeasures(ctx, "tenant", "project", "src")
		if err != nil {
			t.Fatal(err)
		}
		if res.Component.Path != "src" || len(res.Children) != 1 || res.Children[0].Path != "src/main.go" {
			t.Fatalf("src response=%+v", res)
		}
	})

	t.Run("not found", func(t *testing.T) {
		_, err := svc.GetMeasures(ctx, "tenant", "project", "missing")
		if err != shared.ErrNotFound {
			t.Fatalf("missing path err=%v, want ErrNotFound", err)
		}
	})
}
