package taintscan

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
)

func TestJSScanProposesPrototypePollutionFlow(t *testing.T) {
	provider := &fakeJSFacts{document: jsPrototypePollutionDocument(), available: true}
	proposals, audit := &fakeProposer{}, &fakeAudit{}
	coordinator, err := NewJSCoordinator(provider, proposals, taint.DefaultJSCatalog(), audit, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := coordinator.ScanWithCoverage(context.Background(), engID, "/work/target")
	if err != nil {
		t.Fatalf("ScanWithCoverage: %v", err)
	}
	if outcome.Proposed != 1 || len(proposals.calls) != 1 {
		t.Fatalf("javascript prototype-pollution proposals=%d/%d, want one", outcome.Proposed, len(proposals.calls))
	}
	claim, ok := proposals.calls[0].claim.(judgment.SASTClaim)
	if !ok {
		t.Fatalf("claim type=%T", proposals.calls[0].claim)
	}
	if claim.CWE != "CWE-1321" || claim.Rule != "js-proto-pollution-bracket" || claim.Location != "app.js:4" {
		t.Fatalf("claim=%+v", claim)
	}
	if claim.DataFlow == nil || claim.DataFlow.Language != "javascript" || claim.DataFlow.Source.Line != 3 || claim.DataFlow.Sink.Line != 4 {
		t.Fatalf("dataflow=%+v", claim.DataFlow)
	}
	if len(audit.entries) != 1 || audit.entries[0].Metadata["class"] != "prototype_pollution" {
		t.Fatalf("audit=%+v", audit.entries)
	}
}

func jsPrototypePollutionDocument() jsprogram.Document {
	moduleID := "app::<module>"
	return jsprogram.Document{
		SchemaVersion: jsprogram.SchemaVersion,
		Modules:       []jsprogram.Module{{Name: "app", File: "app.js", Pos: jsScanPosJS(1)}},
		Symbols:       []jsprogram.Symbol{{ID: moduleID, Module: "app", QualifiedName: "<module>", Name: "<module>", Kind: jsprogram.SymbolModule, Pos: jsScanPosJS(1)}},
		Imports: []jsprogram.Import{{
			ScopeID: moduleID, Module: "lodash", Alias: "_", Default: true, Pos: jsScanPosJS(2),
		}},
		Calls: []jsprogram.Call{{
			ID: "merge-call", CallerID: moduleID,
			Callee: jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: []string{"_", "merge"}},
			Arguments: []jsprogram.Argument{
				{Value: jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{"target"}}, Pos: jsScanPosJS(4)},
				{Value: jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: []string{"req", "body"}}, ValueID: "request", Pos: jsScanPosJS(4)},
			},
			Pos: jsScanPosJS(4),
		}},
		Values: []jsprogram.Value{{
			ID: "request", ScopeID: moduleID, Kind: jsprogram.ValueReference,
			Ref: jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: []string{"req", "body"}}, Pos: jsScanPosJS(3),
		}},
		FilesSeen: 1, FilesParsed: 1,
	}
}

func jsScanPosJS(line int) jsprogram.Position {
	return jsprogram.Position{File: "app.js", Line: line, Column: 0}
}
