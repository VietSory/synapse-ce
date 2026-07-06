package analysis

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// --- in-package fakes (no infra import from a use-case test) ---

type fakeStore struct{ saved []judgment.Judgment }

func (f *fakeStore) Save(_ context.Context, j judgment.Judgment) error {
	for i := range f.saved {
		if f.saved[i].ID == j.ID {
			f.saved[i] = j
			return nil
		}
	}
	f.saved = append(f.saved, j)
	return nil
}
func (f *fakeStore) ListByEngagement(_ context.Context, eng shared.ID) ([]judgment.Judgment, error) {
	var out []judgment.Judgment
	for _, j := range f.saved {
		if j.EngagementID == eng {
			out = append(out, j)
		}
	}
	return out, nil
}
func (f *fakeStore) SetScoreState(_ context.Context, _, id shared.ID, score int, state judgment.State, expectedVersion int) (judgment.Judgment, error) {
	for i := range f.saved {
		if f.saved[i].ID == id {
			if f.saved[i].Version != expectedVersion {
				return judgment.Judgment{}, shared.ErrConflict
			}
			f.saved[i].EvidenceScore = score
			f.saved[i].State = state
			f.saved[i].Version++
			return f.saved[i], nil
		}
	}
	return judgment.Judgment{}, shared.ErrNotFound
}

type fakeSealer struct {
	kinds []string
	err   error
}

func (f *fakeSealer) Seal(_ context.Context, _ shared.ID, kind string, _ []byte, _ string) (evidence.Evidence, error) {
	if f.err != nil {
		return evidence.Evidence{}, f.err
	}
	f.kinds = append(f.kinds, kind)
	return evidence.Evidence{}, nil
}

type fakeAudit struct{ actions []string }

func (f *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	f.actions = append(f.actions, e.Action)
	return nil
}

type fakeClock struct{}

func (fakeClock) Now() time.Time { return time.Unix(0, 0).UTC() }

type fakeIDs struct{ n int }

func (f *fakeIDs) NewID() shared.ID { f.n++; return shared.ID(fmt.Sprintf("j%d", f.n)) }

func newSvc() (*Service, *fakeStore, *fakeSealer, *fakeAudit) {
	store, sealer, audit := &fakeStore{}, &fakeSealer{}, &fakeAudit{}
	svc, err := NewService(store, sealer, audit, fakeClock{}, &fakeIDs{})
	if err != nil {
		panic(err)
	}
	return svc, store, sealer, audit
}

func reach() judgment.Claim {
	return judgment.ReachabilityClaim{Reachable: "not_reachable", Tier: "tier-1.5", Confidence: 90}
}
func narr() judgment.Claim {
	return judgment.RiskNarrativeClaim{Drivers: []string{"kev"}, Priority: 1}
}

func TestProposeRecordsAtScoreZero(t *testing.T) {
	svc, store, sealer, audit := newSvc()
	j, err := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapReachability, judgment.SubjectFinding, "f1", reach())
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if j.State != judgment.StateProposed || j.EvidenceScore != 0 {
		t.Fatalf("want proposed/0, got %s/%d", j.State, j.EvidenceScore)
	}
	if len(store.saved) != 1 {
		t.Fatalf("want 1 saved, got %d", len(store.saved))
	}
	if len(sealer.kinds) != 1 || sealer.kinds[0] != ProposedEvidenceKind {
		t.Fatalf("want proposed seal, got %v", sealer.kinds)
	}
	if len(audit.actions) != 1 || audit.actions[0] != "judgment.proposed" {
		t.Fatalf("want proposed audit, got %v", audit.actions)
	}
	if _, err := svc.Propose(context.Background(), "", "e1", judgment.CapReachability, judgment.SubjectFinding, "f1", reach()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty proposer: want ErrValidation, got %v", err)
	}
	if _, err := svc.Propose(context.Background(), "agent:s1", "", judgment.CapReachability, judgment.SubjectFinding, "f1", reach()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty engagement: want ErrValidation, got %v", err)
	}
}

func TestVerifyConfirmsSealFirst(t *testing.T) {
	svc, store, sealer, _ := newSvc()
	j, _ := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapReachability, judgment.SubjectFinding, "f1", reach())

	got, err := svc.Verify(context.Background(), "human:bob", "e1", j.ID, 80, "holds", j.Version)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.State != judgment.StateConfirmed || got.EvidenceScore != 80 || !got.Publishable() {
		t.Fatalf("want confirmed/80/publishable, got %s/%d/%v", got.State, got.EvidenceScore, got.Publishable())
	}
	// seal order: proposed BEFORE verdict
	if len(sealer.kinds) != 2 || sealer.kinds[0] != ProposedEvidenceKind || sealer.kinds[1] != VerdictEvidenceKind {
		t.Fatalf("seal order wrong: %v", sealer.kinds)
	}
	_ = store
}

func TestVerifyFailClosedOnSealError(t *testing.T) {
	svc, store, sealer, _ := newSvc()
	j, _ := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapReachability, judgment.SubjectFinding, "f1", reach())
	sealer.err = errors.New("evidence chain down") // verdict seal will fail

	if _, err := svc.Verify(context.Background(), "human:bob", "e1", j.ID, 80, "holds", j.Version); err == nil {
		t.Fatal("want error when verdict seal fails")
	}
	// fail-closed: score/state NOT moved because the seal failed before SetScoreState
	if store.saved[0].State != judgment.StateProposed || store.saved[0].EvidenceScore != 0 {
		t.Fatalf("score moved despite seal failure: %s/%d", store.saved[0].State, store.saved[0].EvidenceScore)
	}
}

func TestVerifyRejectsSelfConfirmAndUngated(t *testing.T) {
	svc, store, sealer, _ := newSvc()
	j, _ := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapReachability, judgment.SubjectFinding, "f1", reach())
	beforeSeals := len(sealer.kinds)

	// proposer == verifier
	if _, err := svc.Verify(context.Background(), "agent:s1", "e1", j.ID, 90, "x", j.Version); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("self-confirm: want ErrValidation, got %v", err)
	}
	// no verdict seal written, score unchanged
	if len(sealer.kinds) != beforeSeals || store.saved[0].EvidenceScore != 0 {
		t.Fatal("self-confirm leaked a seal or moved the score")
	}

	// ungated capability cannot take a verdict
	jn, _ := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapRiskNarrative, judgment.SubjectFinding, "f2", narr())
	if _, err := svc.Verify(context.Background(), "human:bob", "e1", jn.ID, 90, "x", jn.Version); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("ungated verify: want ErrValidation, got %v", err)
	}
}

func TestAcceptUngated(t *testing.T) {
	svc, _, _, audit := newSvc()
	jn, _ := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapRiskNarrative, judgment.SubjectFinding, "f1", narr())
	got, err := svc.Accept(context.Background(), "human:bob", "e1", jn.ID, jn.Version)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if got.State != judgment.StateConfirmed || !got.Publishable() {
		t.Fatalf("want confirmed/publishable, got %s/%v", got.State, got.Publishable())
	}
	if audit.actions[len(audit.actions)-1] != "judgment.accepted" {
		t.Fatalf("want accepted audit, got %v", audit.actions)
	}
	// self-accept rejected
	jn2, _ := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapRiskNarrative, judgment.SubjectFinding, "f3", narr())
	if _, err := svc.Accept(context.Background(), "agent:s1", "e1", jn2.ID, jn2.Version); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("self-accept: want ErrValidation, got %v", err)
	}
}

func TestVerifyConflict(t *testing.T) {
	svc, _, _, _ := newSvc()
	j, _ := svc.Propose(context.Background(), "agent:s1", "e1", judgment.CapReachability, judgment.SubjectFinding, "f1", reach())
	// wrong expectedVersion → conflict (seal still happens; orphan acceptable by design)
	if _, err := svc.Verify(context.Background(), "human:bob", "e1", j.ID, 80, "holds", j.Version+1); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
}
