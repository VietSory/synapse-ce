package findings

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func confirmedSAST() judgment.Judgment {
	return judgment.Judgment{
		ID: "j-9", EngagementID: "eng-1", Capability: judgment.CapSAST,
		SubjectKind: judgment.SubjectDataFlow, SubjectID: "flow-9",
		Claim: judgment.SASTClaim{CWE: "CWE-89", Location: "app/dao.Find", Rule: "taint-sqli"},
		State: judgment.StateConfirmed,
	}
}

func TestRecordConfirmedSAST(t *testing.T) {
	repo := &fakeRepo{}
	audit := &fakeAudit{}
	svc := newSvc(repo, &fakeComments{}, audit)
	if err := svc.RecordConfirmedSAST(context.Background(), "human:bob", confirmedSAST()); err != nil {
		t.Fatalf("record: %v", err)
	}
	if len(repo.upserted) != 1 {
		t.Fatalf("want 1 sast finding persisted, got %d", len(repo.upserted))
	}
	f := repo.upserted[0]
	if f.Kind != finding.KindSAST || f.Class != finding.ClassFirstParty || f.DedupKey != "sast:ai:j-9" {
		t.Fatalf("sast finding wrong kind/class/dedup: %+v", f)
	}
	if f.CWE != "CWE-89" || f.ProposedBy != "" {
		t.Errorf("CWE must carry through + ProposedBy empty (the gate ran at the judgment layer): %+v", f)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "finding.sast_promoted" {
		t.Errorf("promotion must be audited, got %+v", audit.entries)
	}
	if audit.entries[0].Actor != "human:bob" {
		t.Errorf("promotion must be attributed to the verifier (the trigger), not the system proposer; got %q", audit.entries[0].Actor)
	}
}

func TestRecordConfirmedSASTRejectsWrongInput(t *testing.T) {
	svc := newSvc(&fakeRepo{}, &fakeComments{}, &fakeAudit{})
	// not a sast capability
	j := confirmedSAST()
	j.Capability = judgment.CapReachability
	if err := svc.RecordConfirmedSAST(context.Background(), "human:bob", j); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("non-sast capability must be rejected, got %v", err)
	}
	// sast capability but the claim isn't a SASTClaim (defense-in-depth)
	j2 := confirmedSAST()
	j2.Claim = judgment.ReachabilityClaim{Reachable: "unknown", Tier: "tier-0"}
	if err := svc.RecordConfirmedSAST(context.Background(), "human:bob", j2); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("a sast judgment without a SASTClaim must be rejected, got %v", err)
	}
}
