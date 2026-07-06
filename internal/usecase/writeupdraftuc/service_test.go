package writeupdraftuc

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeupdraft"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// --- in-test doubles (keep the usecase test free of infrastructure imports) ---

type fakeStore struct {
	saved   []writeupdraft.Draft
	getErr  error
	saveErr error
}

func (f *fakeStore) Save(_ context.Context, d writeupdraft.Draft) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	for i := range f.saved {
		if f.saved[i].ID == d.ID {
			f.saved[i] = d
			return nil
		}
	}
	f.saved = append(f.saved, d)
	return nil
}

func (f *fakeStore) Get(_ context.Context, engagementID, id shared.ID) (writeupdraft.Draft, error) {
	if f.getErr != nil {
		return writeupdraft.Draft{}, f.getErr
	}
	for _, d := range f.saved {
		if d.EngagementID == engagementID && d.ID == id {
			return d, nil
		}
	}
	return writeupdraft.Draft{}, shared.ErrNotFound
}

func (f *fakeStore) ListByEngagement(_ context.Context, engagementID shared.ID) ([]writeupdraft.Draft, error) {
	var out []writeupdraft.Draft
	for _, d := range f.saved {
		if d.EngagementID == engagementID {
			out = append(out, d)
		}
	}
	return out, nil
}

var _ ports.WriteupDraftStore = (*fakeStore)(nil)

type tickClock struct{ t time.Time }

func newTickClock() *tickClock {
	return &tickClock{t: time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)}
}

func (c *tickClock) Now() time.Time { c.t = c.t.Add(time.Second); return c.t }

type recordingAudit struct {
	entries []ports.AuditEntry
	failOn  string
}

func (a *recordingAudit) Record(_ context.Context, e ports.AuditEntry) error {
	if a.failOn != "" && e.Action == a.failOn {
		return errors.New("audit boom")
	}
	a.entries = append(a.entries, e)
	return nil
}

func (a *recordingAudit) actions() []string {
	out := make([]string, len(a.entries))
	for i, e := range a.entries {
		out[i] = e.Action
	}
	return out
}

type seqIDs struct{ n int }

func (g *seqIDs) NewID() shared.ID { g.n++; return shared.ID(fmt.Sprintf("wd:%d", g.n)) }

type fakeApplier struct {
	calls                     int
	gotEng, gotFind           shared.ID
	gotDesc, gotRem, gotActor string
	err                       error
}

func (f *fakeApplier) ApplyWriteupDraft(_ context.Context, actor string, engagementID, findingID shared.ID, description, remediation string) error {
	f.calls++
	f.gotActor, f.gotEng, f.gotFind, f.gotDesc, f.gotRem = actor, engagementID, findingID, description, remediation
	return f.err
}

func newSvc(t *testing.T) (*Service, *fakeStore, *recordingAudit) {
	t.Helper()
	store := &fakeStore{}
	audit := &recordingAudit{}
	svc, err := NewService(store, audit, newTickClock(), &seqIDs{})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, store, audit
}

// --- tests ---

func TestNewServiceRejectsNilDeps(t *testing.T) {
	if _, err := NewService(nil, &recordingAudit{}, newTickClock(), &seqIDs{}); !errors.Is(err, shared.ErrValidation) {
		t.Error("nil store must fail")
	}
	if _, err := NewService(&fakeStore{}, nil, newTickClock(), &seqIDs{}); !errors.Is(err, shared.ErrValidation) {
		t.Error("nil audit must fail")
	}
}

func TestProposePersistsAndAudits(t *testing.T) {
	svc, store, audit := newSvc(t)
	d, err := svc.Propose(context.Background(), "agent:writer", "eng:1", "find:1", "Stored XSS.", "Encode output.")
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if d.State != writeupdraft.StateProposed || d.ProposedBy != "agent:writer" {
		t.Errorf("unexpected draft: %+v", d)
	}
	if len(store.saved) != 1 || store.saved[0].ID != d.ID {
		t.Errorf("draft not persisted: %+v", store.saved)
	}
	if got := audit.actions(); len(got) != 1 || got[0] != "writeup_draft.proposed" {
		t.Errorf("audit actions = %v", got)
	}
}

func TestEditRevisesText(t *testing.T) {
	svc, _, audit := newSvc(t)
	d, _ := svc.Propose(context.Background(), "agent:writer", "eng:1", "find:1", "draft", "")
	edited, err := svc.Edit(context.Background(), "user:rev", "eng:1", d.ID, "revised", "fix it")
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	if edited.Description != "revised" || edited.Remediation != "fix it" {
		t.Errorf("edit did not apply: %+v", edited)
	}
	if !edited.UpdatedAt.After(d.UpdatedAt) {
		t.Error("edit should advance UpdatedAt")
	}
	if got := audit.actions(); got[len(got)-1] != "writeup_draft.edited" {
		t.Errorf("last audit action = %q", got[len(got)-1])
	}
}

func TestAcceptSignOffAndSoD(t *testing.T) {
	svc, store, audit := newSvc(t)
	d, _ := svc.Propose(context.Background(), "agent:writer", "eng:1", "find:1", "draft", "")

	// SoD: the proposer cannot accept its own draft, and nothing extra is persisted/audited.
	if _, err := svc.Accept(context.Background(), "agent:writer", "eng:1", d.ID); !errors.Is(err, shared.ErrValidation) {
		t.Error("proposer must not sign off its own draft")
	}
	if store.saved[0].State != writeupdraft.StateProposed {
		t.Error("a rejected SoD acceptance must not mutate the stored draft")
	}

	acc, err := svc.Accept(context.Background(), "user:reviewer", "eng:1", d.ID)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if acc.State != writeupdraft.StateAccepted || acc.DecidedBy != "user:reviewer" {
		t.Errorf("accept wrong: %+v", acc)
	}
	if got := audit.actions(); got[len(got)-1] != "writeup_draft.accepted" {
		t.Errorf("last audit action = %q", got[len(got)-1])
	}
	// Terminal: a second decision fails.
	if _, err := svc.Reject(context.Background(), "user:reviewer", "eng:1", d.ID); !errors.Is(err, shared.ErrValidation) {
		t.Error("rejecting an accepted draft must fail")
	}
}

func TestRejectAndMissing(t *testing.T) {
	svc, _, audit := newSvc(t)
	d, _ := svc.Propose(context.Background(), "agent:writer", "eng:1", "find:1", "draft", "")
	rej, err := svc.Reject(context.Background(), "user:reviewer", "eng:1", d.ID)
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if rej.State != writeupdraft.StateRejected {
		t.Errorf("reject wrong: %+v", rej)
	}
	if got := audit.actions(); got[len(got)-1] != "writeup_draft.rejected" {
		t.Errorf("last audit action = %q", got[len(got)-1])
	}
	// A missing draft fails to load.
	if _, err := svc.Accept(context.Background(), "user:reviewer", "eng:1", "nope"); err == nil {
		t.Error("accepting a missing draft must error")
	}
}

func TestAcceptAppliesToFinding(t *testing.T) {
	svc, _, audit := newSvc(t)
	ap := &fakeApplier{}
	svc.SetFindingWriteupApplier(ap)
	d, _ := svc.Propose(context.Background(), "agent:writer", "eng:1", "find:1", "the issue", "the fix")
	acc, err := svc.Accept(context.Background(), "user:reviewer", "eng:1", d.ID)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	// the accepted draft's finding + prose are applied, attributed to the signing human
	if ap.calls != 1 || ap.gotEng != "eng:1" || ap.gotFind != "find:1" || ap.gotDesc != "the issue" || ap.gotRem != "the fix" || ap.gotActor != "user:reviewer" {
		t.Fatalf("apply not called with the draft's finding/prose/actor: %+v", ap)
	}
	if acc.State != writeupdraft.StateAccepted {
		t.Errorf("draft should be accepted: %+v", acc)
	}
	if got := audit.actions(); got[len(got)-1] != "writeup_draft.accepted" {
		t.Errorf("last audit = %q", got[len(got)-1])
	}
}

func TestAcceptApplyFailureAbortsAccept(t *testing.T) {
	svc, store, audit := newSvc(t)
	svc.SetFindingWriteupApplier(&fakeApplier{err: errors.New("finding not in engagement")})
	d, _ := svc.Propose(context.Background(), "agent:writer", "eng:1", "find:1", "desc", "")
	auditsBefore := len(audit.entries)
	if _, err := svc.Accept(context.Background(), "user:reviewer", "eng:1", d.ID); err == nil {
		t.Fatal("accept must fail when the apply fails")
	}
	// hard-fail: the draft stays Proposed (the acceptance is never persisted) and no accepted-audit is written
	if store.saved[0].State != writeupdraft.StateProposed {
		t.Errorf("a failed apply must leave the draft Proposed, got %q", store.saved[0].State)
	}
	if len(audit.entries) != auditsBefore {
		t.Errorf("a failed apply must not write the accepted audit (got %d new)", len(audit.entries)-auditsBefore)
	}
}

func TestRejectDoesNotApply(t *testing.T) {
	svc, _, _ := newSvc(t)
	ap := &fakeApplier{}
	svc.SetFindingWriteupApplier(ap)
	d, _ := svc.Propose(context.Background(), "agent:writer", "eng:1", "find:1", "desc", "")
	if _, err := svc.Reject(context.Background(), "user:reviewer", "eng:1", d.ID); err != nil {
		t.Fatalf("reject: %v", err)
	}
	if ap.calls != 0 {
		t.Errorf("reject must NOT apply to a finding, got %d calls", ap.calls)
	}
}

func TestListByEngagement(t *testing.T) {
	svc, _, _ := newSvc(t)
	_, _ = svc.Propose(context.Background(), "agent:w", "eng:1", "find:1", "a", "")
	_, _ = svc.Propose(context.Background(), "agent:w", "eng:1", "find:2", "b", "")
	_, _ = svc.Propose(context.Background(), "agent:w", "eng:2", "find:3", "c", "")
	got, err := svc.ListByEngagement(context.Background(), "eng:1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("want 2 drafts for eng:1, got %d", len(got))
	}
}
