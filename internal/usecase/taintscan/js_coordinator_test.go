package taintscan

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeJSFacts struct {
	document jsprogram.Document
	available bool
	err error
}

func (f *fakeJSFacts) JSFacts(context.Context, string) (jsprogram.Document, bool, error) {
	return f.document, f.available, f.err
}

func TestJSScanProposesResolvedCommandFlow(t *testing.T) {
	provider := &fakeJSFacts{document: jsCommandDocument(), available: true}
	proposals, audit := &fakeProposer{}, &fakeAudit{}
	coordinator, err := NewJSCoordinator(provider, proposals, taint.DefaultJSCatalog(), audit, fixedClock{})
	if err != nil { t.Fatal(err) }
	outcome, err := coordinator.ScanWithCoverage(context.Background(), engID, "/work/target")
	if err != nil { t.Fatalf("ScanWithCoverage: %v", err) }
	if outcome.Proposed != 1 || len(proposals.calls) != 1 {
		t.Fatalf("javascript proposals=%d/%d, want one", outcome.Proposed, len(proposals.calls))
	}
	if outcome.Coverage.Status != ports.AnalysisCoverageComplete || !outcome.Coverage.Complete {
		t.Fatalf("coverage=%+v", outcome.Coverage)
	}
	proposal := proposals.calls[0]
	claim, ok := proposal.claim.(judgment.SASTClaim)
	if !ok { t.Fatalf("claim type=%T", proposal.claim) }
	if proposal.proposer != jsProposerActor || proposal.capability != judgment.CapSAST || proposal.subjectKind != judgment.SubjectDataFlow {
		t.Fatalf("proposal lifecycle=%+v", proposal)
	}
	if claim.CWE != "CWE-78" || claim.Rule != "javascript-taint-command" || claim.Location != "app.ts:4" {
		t.Fatalf("claim=%+v", claim)
	}
	if claim.DataFlow == nil || claim.DataFlow.Language != "javascript" || !claim.DataFlow.CoverageComplete || claim.DataFlow.Source.Line != 3 || claim.DataFlow.Sink.Line != 4 {
		t.Fatalf("dataflow=%+v", claim.DataFlow)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "judgment.javascript_taint_proposed" {
		t.Fatalf("audit=%+v", audit.entries)
	}
}

func TestJSScanKeepsPositiveEvidenceWhenResolutionIsPartial(t *testing.T) {
	document := jsCommandDocument()
	// res.send cannot be semantically import-resolved, so adding this call makes coverage partial.
	document.Calls = append(document.Calls, jsprogram.Call{
		ID: "send", CallerID: "app::<module>",
		Callee: jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: []string{"res", "send"}},
		Arguments: []jsprogram.Argument{{Value: jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: []string{"req", "query"}}, ValueID: "request", Pos: jsScanPos(5)}},
		Pos: jsScanPos(5),
	})
	coordinator, _ := NewJSCoordinator(&fakeJSFacts{document: document, available: true}, &fakeProposer{}, taint.DefaultJSCatalog(), &fakeAudit{}, fixedClock{})
	outcome, err := coordinator.ScanWithCoverage(context.Background(), engID, "/work/target")
	if err != nil { t.Fatal(err) }
	if outcome.Coverage.Status != ports.AnalysisCoveragePartial || outcome.Coverage.Complete || outcome.Proposed < 1 {
		t.Fatalf("partial positive outcome=%+v", outcome)
	}
}

func TestJSScanNoCoverageProposesNothing(t *testing.T) {
	for _, provider := range []*fakeJSFacts{{available: false}, {err: errors.New("parser failed")}} {
		proposals, audit := &fakeProposer{}, &fakeAudit{}
		coordinator, _ := NewJSCoordinator(provider, proposals, taint.DefaultJSCatalog(), audit, fixedClock{})
		outcome, err := coordinator.ScanWithCoverage(context.Background(), engID, "/work/target")
		if err == nil || outcome.Proposed != 0 || len(proposals.calls) != 0 || len(audit.entries) != 0 {
			t.Fatalf("no coverage must propose nothing: outcome=%+v err=%v", outcome, err)
		}
	}
}

func TestJSScanNoSourceIsNotApplicable(t *testing.T) {
	coordinator, _ := NewJSCoordinator(
		&fakeJSFacts{document: jsprogram.Document{SchemaVersion: jsprogram.SchemaVersion}, available: true},
		&fakeProposer{}, taint.DefaultJSCatalog(), &fakeAudit{}, fixedClock{},
	)
	outcome, err := coordinator.ScanWithCoverage(context.Background(), engID, "/work/target")
	if err != nil { t.Fatal(err) }
	if outcome.Coverage.Status != ports.AnalysisCoverageNotApplicable || outcome.Coverage.Reason != ports.AnalysisReasonNoSource {
		t.Fatalf("coverage=%+v", outcome.Coverage)
	}
}

func jsCommandDocument() jsprogram.Document {
	return jsprogram.Document{
		SchemaVersion: jsprogram.SchemaVersion,
		Modules: []jsprogram.Module{{Name: "app", File: "app.ts", Pos: jsScanPos(1)}},
		Symbols: []jsprogram.Symbol{{ID: "app::<module>", Module: "app", QualifiedName: "<module>", Name: "<module>", Kind: jsprogram.SymbolModule, Pos: jsScanPos(1)}},
		Imports: []jsprogram.Import{{ScopeID: "app::<module>", Module: "child_process", Name: "exec", Alias: "run", Pos: jsScanPos(2)}},
		Calls: []jsprogram.Call{{
			ID: "exec", CallerID: "app::<module>", Callee: jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{"run"}},
			Arguments: []jsprogram.Argument{{Value: jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: []string{"req", "query"}}, ValueID: "request", Pos: jsScanPos(4)}}, Pos: jsScanPos(4),
		}},
		Values: []jsprogram.Value{{
			ID: "request", ScopeID: "app::<module>", Kind: jsprogram.ValueReference,
			Ref: jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: []string{"req", "query"}}, Pos: jsScanPos(3),
		}},
		FilesSeen: 1, FilesParsed: 1,
	}
}

func jsScanPos(line int) jsprogram.Position { return jsprogram.Position{File: "app.ts", Line: line, Column: 0} }
