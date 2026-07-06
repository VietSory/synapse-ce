package memory

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/threatmodel"
)

func TestThreatModelStoreSaveGetUpsert(t *testing.T) {
	ctx := context.Background()
	s := NewThreatModelStore()

	// empty store: not found
	if _, ok, err := s.Get(ctx, "eng-1"); ok || err != nil {
		t.Fatalf("empty store must return ok=false, no error; got ok=%v err=%v", ok, err)
	}

	m := threatmodel.Model{Flows: []threatmodel.DataFlow{{ID: "f1", From: "a", To: "b"}}}
	if err := s.Save(ctx, "eng-1", "tenant-1", m); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Get(ctx, "eng-1")
	if err != nil || !ok || len(got.Flows) != 1 {
		t.Fatalf("save→get round trip failed: %+v ok=%v err=%v", got, ok, err)
	}

	// upsert replaces the engagement's model
	if err := s.Save(ctx, "eng-1", "tenant-1", threatmodel.Model{}); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s.Get(ctx, "eng-1"); len(got.Flows) != 0 {
		t.Fatalf("a second Save must replace the model, got %+v", got)
	}

	// engagement isolation: a different engagement is independent
	if _, ok, _ := s.Get(ctx, "eng-2"); ok {
		t.Error("a different engagement must not see eng-1's model")
	}
}
