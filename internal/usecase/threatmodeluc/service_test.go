package threatmodeluc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/threatmodel"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeStore struct {
	savedEng, savedTenant shared.ID
	saved                 threatmodel.Model
	got                   threatmodel.Model
	getOK                 bool
}

func (f *fakeStore) Save(_ context.Context, eng, tenant shared.ID, m threatmodel.Model) error {
	f.savedEng, f.savedTenant, f.saved = eng, tenant, m
	return nil
}
func (f *fakeStore) Get(_ context.Context, _ shared.ID) (threatmodel.Model, bool, error) {
	return f.got, f.getOK, nil
}

type fakeAudit struct{ entries []ports.AuditEntry }

func (f *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	f.entries = append(f.entries, e)
	return nil
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

func sampleModel() threatmodel.Model {
	return threatmodel.Model{
		Boundaries: []threatmodel.TrustBoundary{{ID: "internet"}, {ID: "vpc"}},
		Components: []threatmodel.Component{
			{ID: "user", Kind: threatmodel.KindExternalEntity, Boundary: "internet"},
			{ID: "api", Kind: threatmodel.KindProcess, Boundary: "vpc"},
		},
		Flows: []threatmodel.DataFlow{{ID: "f1", From: "user", To: "api"}}, // crosses internet→vpc
	}
}

func TestIngestValidatesSavesAudits(t *testing.T) {
	st, au := &fakeStore{}, &fakeAudit{}
	s, err := NewService(st, au, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	delta, err := s.Ingest(context.Background(), "alice", "tenant-1", "eng-1", sampleModel())
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if st.savedEng != "eng-1" || st.savedTenant != "tenant-1" || len(st.saved.Flows) != 1 {
		t.Fatalf("model must be saved with engagement + tenant: %+v", st)
	}
	if len(au.entries) != 1 || au.entries[0].Action != "threat_model.ingest" || au.entries[0].Actor != "alice" || au.entries[0].Target != "eng-1" {
		t.Fatalf("ingest must be audited (attributable): %+v", au.entries)
	}
	if au.entries[0].Metadata["crossings"] != "1" {
		t.Errorf("audit metadata should record the boundary-crossing count, got %q", au.entries[0].Metadata["crossings"])
	}
	// First ingest (no prior model): the delta reports everything as added, including the one crossing.
	if len(delta.AddedComponents) != 2 || len(delta.AddedFlows) != 1 || len(delta.NewCrossings) != 1 {
		t.Errorf("first-ingest delta should report all added + the one new crossing: %+v", delta)
	}
	if au.entries[0].Metadata["added_components"] != "2" || au.entries[0].Metadata["new_crossings"] != "1" {
		t.Errorf("audit metadata should record the delta counts, got %+v", au.entries[0].Metadata)
	}
}

func TestIngestComputesDeltaVsPrior(t *testing.T) {
	// The store returns a PRIOR model; Ingest must diff the new model against it.
	st := &fakeStore{got: sampleModel(), getOK: true}
	au := &fakeAudit{}
	s, _ := NewService(st, au, fixedClock{})

	// Next: add a db data-store in the vpc + a flow api→db (same boundary → NOT a new crossing); remove nothing.
	next := sampleModel()
	next.Components = append(next.Components, threatmodel.Component{ID: "db", Kind: threatmodel.KindDataStore, Boundary: "vpc"})
	next.Flows = append(next.Flows, threatmodel.DataFlow{ID: "f2", From: "api", To: "db"})

	delta, err := s.Ingest(context.Background(), "alice", "t", "eng-1", next)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(delta.AddedComponents) != 1 || delta.AddedComponents[0].ID != "db" {
		t.Errorf("want db added, got %+v", delta.AddedComponents)
	}
	if len(delta.AddedFlows) != 1 || delta.AddedFlows[0].ID != "f2" {
		t.Errorf("want f2 added, got %+v", delta.AddedFlows)
	}
	if len(delta.RemovedComponents) != 0 || len(delta.RemovedFlows) != 0 {
		t.Errorf("nothing removed; got comps=%+v flows=%+v", delta.RemovedComponents, delta.RemovedFlows)
	}
	if len(delta.NewCrossings) != 0 {
		t.Errorf("api→db stays within the vpc → no new crossing, got %+v", delta.NewCrossings)
	}
	if au.entries[0].Metadata["added_components"] != "1" || au.entries[0].Metadata["new_crossings"] != "0" {
		t.Errorf("audit metadata should record the delta counts, got %+v", au.entries[0].Metadata)
	}
}

func TestIngestRejectsInvalidModel(t *testing.T) {
	st := &fakeStore{}
	s, _ := NewService(st, &fakeAudit{}, fixedClock{})
	m := sampleModel()
	m.Flows[0].From = "ghost" // dangling endpoint → domain Validate fails
	if _, err := s.Ingest(context.Background(), "alice", "t", "eng-1", m); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an invalid model must be rejected with ErrValidation, got %v", err)
	}
	if st.savedEng != "" {
		t.Error("an invalid model must NOT be persisted")
	}
}

func TestIngestRejectsOversizeBeforeValidate(t *testing.T) {
	st := &fakeStore{}
	s, _ := NewService(st, &fakeAudit{}, fixedClock{})
	// more components than the cap; rejected on size BEFORE the (linear) Validate even runs
	m := threatmodel.Model{Components: make([]threatmodel.Component, maxComponents+1)}
	if _, err := s.Ingest(context.Background(), "alice", "t", "eng-1", m); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an oversize model must be rejected, got %v", err)
	}
	if st.savedEng != "" {
		t.Error("an oversize model must NOT be persisted")
	}
}

func TestIngestRequiresEngagement(t *testing.T) {
	s, _ := NewService(&fakeStore{}, &fakeAudit{}, fixedClock{})
	if _, err := s.Ingest(context.Background(), "alice", "t", "", sampleModel()); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("empty engagement id must be rejected, got %v", err)
	}
}

func TestNewServiceValidatesDeps(t *testing.T) {
	if _, err := NewService(nil, &fakeAudit{}, fixedClock{}); !errors.Is(err, shared.ErrValidation) {
		t.Error("nil store must fail")
	}
	if _, err := NewService(&fakeStore{}, nil, fixedClock{}); !errors.Is(err, shared.ErrValidation) {
		t.Error("nil audit must fail")
	}
	if _, err := NewService(&fakeStore{}, &fakeAudit{}, nil); !errors.Is(err, shared.ErrValidation) {
		t.Error("nil clock must fail")
	}
}

func TestGetDelegates(t *testing.T) {
	st := &fakeStore{got: sampleModel(), getOK: true}
	s, _ := NewService(st, &fakeAudit{}, fixedClock{})
	m, ok, err := s.Get(context.Background(), "eng-1")
	if err != nil || !ok || len(m.Flows) != 1 {
		t.Fatalf("get must delegate to the store: %+v ok=%v err=%v", m, ok, err)
	}
}
