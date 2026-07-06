package crosscheckjudge

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeProposer struct {
	existing []judgment.Judgment
	proposed []judgment.Judgment
	failAt   int // 1-based; fail the Nth Propose
	n        int
}

func (f *fakeProposer) List(context.Context, shared.ID) ([]judgment.Judgment, error) {
	return f.existing, nil
}
func (f *fakeProposer) Propose(_ context.Context, proposer string, eng shared.ID, cap judgment.Capability, sk judgment.SubjectKind, sid shared.ID, claim judgment.Claim) (judgment.Judgment, error) {
	f.n++
	if f.failAt != 0 && f.n == f.failAt {
		return judgment.Judgment{}, errors.New("propose boom")
	}
	j := judgment.Judgment{ID: shared.ID("j-" + strconv.Itoa(f.n)), EngagementID: eng, Capability: cap, SubjectKind: sk, SubjectID: sid, Claim: claim, ProposedBy: proposer, State: judgment.StateProposed}
	f.proposed = append(f.proposed, j)
	return j, nil
}

type fakeAudit struct{ entries []ports.AuditEntry }

func (a *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

func item(adv, comp, ver string, reporters, missing []string) vulnerability.CrossCheckItem {
	return vulnerability.CrossCheckItem{AdvisoryID: adv, Component: comp, Version: ver, Reporters: reporters, Missing: missing}
}
func report(items ...vulnerability.CrossCheckItem) vulnerability.CrossCheckReport {
	return vulnerability.CrossCheckReport{Disagreements: items}
}

func TestRecordMintsPerDisagreement(t *testing.T) {
	fp, au := &fakeProposer{}, &fakeAudit{}
	c, err := NewCoordinator(fp, au, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	n, err := c.Record(context.Background(), "eng-1", report(
		item("CVE-1", "pkgA", "1.0", []string{"osv"}, []string{"owned"}),
		item("CVE-2", "pkgB", "2.0", []string{"grype"}, []string{"owned"}),
	))
	if err != nil || n != 2 || len(fp.proposed) != 2 {
		t.Fatalf("want 2 minted, got n=%d proposed=%d err=%v", n, len(fp.proposed), err)
	}
	p := fp.proposed[0]
	if p.Capability != judgment.CapCorrelation || p.SubjectKind != judgment.SubjectVulnerability || p.ProposedBy != "system:cross-check" {
		t.Fatalf("propose wiring wrong: %+v", p)
	}
	if p.SubjectID != "vuln:CVE-1:pkgA:1.0" {
		t.Errorf("stable subject id wrong (must follow the vulnDedupKey convention): %q", p.SubjectID)
	}
	cc, ok := p.Claim.(judgment.CorrelationClaim)
	if !ok || !reflect.DeepEqual(cc.Reporters, []string{"osv"}) || !reflect.DeepEqual(cc.Missing, []string{"owned"}) {
		t.Errorf("claim built wrong: %#v", p.Claim)
	}
	if len(au.entries) != 2 || au.entries[0].Action != "judgment.correlation_proposed" {
		t.Errorf("each mint must be audited, got %+v", au.entries)
	}
}

func TestRecordIdempotent(t *testing.T) {
	fp := &fakeProposer{existing: []judgment.Judgment{{Capability: judgment.CapCorrelation, SubjectID: "vuln:CVE-1:pkgA:1.0"}}}
	c, _ := NewCoordinator(fp, &fakeAudit{}, fixedClock{})
	n, _ := c.Record(context.Background(), "eng-1", report(
		item("CVE-1", "pkgA", "1.0", []string{"osv"}, []string{"owned"}), // already recorded → skip
		item("CVE-2", "pkgB", "2.0", []string{"osv"}, []string{"owned"}), // new → mint
	))
	if n != 1 || len(fp.proposed) != 1 || fp.proposed[0].SubjectID != "vuln:CVE-2:pkgB:2.0" {
		t.Fatalf("must skip the already-recorded subject, mint only the new: n=%d proposed=%+v", n, fp.proposed)
	}
}

func TestRecordDeduplicatesWithinReport(t *testing.T) {
	fp := &fakeProposer{}
	c, _ := NewCoordinator(fp, &fakeAudit{}, fixedClock{})
	n, _ := c.Record(context.Background(), "eng-1", report(
		item("CVE-1", "a", "1", []string{"osv"}, []string{"owned"}),
		item("CVE-1", "a", "1", []string{"grype"}, []string{"owned"}), // same subject id
	))
	if n != 1 || len(fp.proposed) != 1 {
		t.Fatalf("a duplicate subject within one report must mint once, got n=%d", n)
	}
}

func TestRecordSkipsIdlessDisagreement(t *testing.T) {
	fp := &fakeProposer{}
	c, _ := NewCoordinator(fp, &fakeAudit{}, fixedClock{})
	n, err := c.Record(context.Background(), "eng-1", report(
		item("", "pkgX", "1.0", []string{"osv"}, []string{"owned"}),      // no advisory id → no clean subject → skipped
		item("CVE-7", "pkgY", "2.0", []string{"osv"}, []string{"owned"}), // minted
	))
	if err != nil || n != 1 || len(fp.proposed) != 1 || fp.proposed[0].SubjectID != "vuln:CVE-7:pkgY:2.0" {
		t.Fatalf("an id-less disagreement must be skipped (only CVE-7 minted): n=%d proposed=%+v", n, fp.proposed)
	}
}

func TestRecordNoDisagreements(t *testing.T) {
	fp := &fakeProposer{}
	c, _ := NewCoordinator(fp, &fakeAudit{}, fixedClock{})
	n, err := c.Record(context.Background(), "eng-1", vulnerability.CrossCheckReport{})
	if err != nil || n != 0 || len(fp.proposed) != 0 {
		t.Fatalf("no disagreements → 0 minted, no propose; got n=%d err=%v", n, err)
	}
}

func TestRecordProposeErrorAborts(t *testing.T) {
	fp := &fakeProposer{failAt: 2}
	c, _ := NewCoordinator(fp, &fakeAudit{}, fixedClock{})
	n, err := c.Record(context.Background(), "eng-1", report(
		item("CVE-1", "a", "1", []string{"osv"}, []string{"owned"}),
		item("CVE-2", "b", "2", []string{"osv"}, []string{"owned"}),
	))
	if err == nil || n != 1 {
		t.Fatalf("a propose error must abort with the partial count 1, got n=%d err=%v", n, err)
	}
}

func TestRecordRequiresEngagement(t *testing.T) {
	c, _ := NewCoordinator(&fakeProposer{}, &fakeAudit{}, fixedClock{})
	if _, err := c.Record(context.Background(), "", report(item("CVE-1", "a", "1", []string{"osv"}, []string{"owned"}))); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("empty engagement must be rejected, got %v", err)
	}
}

func TestNewCoordinatorValidates(t *testing.T) {
	if _, err := NewCoordinator(nil, &fakeAudit{}, fixedClock{}); !errors.Is(err, shared.ErrValidation) {
		t.Error("nil proposer must fail")
	}
	if _, err := NewCoordinator(&fakeProposer{}, nil, fixedClock{}); !errors.Is(err, shared.ErrValidation) {
		t.Error("nil audit must fail")
	}
	if _, err := NewCoordinator(&fakeProposer{}, &fakeAudit{}, nil); !errors.Is(err, shared.ErrValidation) {
		t.Error("nil clock must fail")
	}
}
