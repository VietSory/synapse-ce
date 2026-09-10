package taint

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
)

func TestJSPrototypePollutionFindsResolvedLodashMerge(t *testing.T) {
	doc := jsPrototypePollutionDocument("lodash", "_", true, []string{"_", "merge"})
	paths := prototypePollutionPathsForTest(t, doc)
	if len(paths) != 1 {
		t.Fatalf("prototype-pollution paths = %d, want 1: %#v", len(paths), paths)
	}
	got := paths[0]
	if got.Class != TaintPrototypePollution || got.CWE != "CWE-1321" || got.Rule != "js-proto-pollution-bracket" {
		t.Fatalf("unexpected prototype-pollution finding: %#v", got)
	}
	if got.SourceID != "request" || got.CallID != "merge-call" || got.Callee != "lodash.merge" {
		t.Fatalf("unexpected prototype-pollution witness: %#v", got)
	}
}

func TestJSPrototypePollutionFindsStandaloneLodashMergePackage(t *testing.T) {
	doc := jsPrototypePollutionDocument("lodash.merge", "merge", true, []string{"merge"})
	paths := prototypePollutionPathsForTest(t, doc)
	if len(paths) != 1 || paths[0].Callee != "lodash.merge" {
		t.Fatalf("standalone lodash.merge paths = %#v", paths)
	}
}

func TestJSPrototypePollutionDoesNotMatchGenericApplicationMerge(t *testing.T) {
	pos := func(line int) jsprogram.Position { return jsprogram.Position{File: "app.js", Line: line} }
	moduleID := "app::<module>"
	doc := jsprogram.Document{
		SchemaVersion: jsprogram.SchemaVersion,
		Modules:       []jsprogram.Module{{Name: "app", File: "app.js", Pos: pos(1)}},
		Symbols:       []jsprogram.Symbol{{ID: moduleID, Module: "app", QualifiedName: "<module>", Name: "<module>", Kind: jsprogram.SymbolModule, Pos: pos(1)}},
		Calls: []jsprogram.Call{{
			ID: "merge-call", CallerID: moduleID,
			Callee: jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: []string{"custom", "merge"}},
			Arguments: []jsprogram.Argument{
				{Value: jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{"target"}}, Pos: pos(3)},
				{Value: jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: []string{"req", "body"}}, ValueID: "request", Pos: pos(3)},
			},
			Pos: pos(3),
		}},
		Values: []jsprogram.Value{{
			ID: "request", ScopeID: moduleID, Kind: jsprogram.ValueReference,
			Ref: jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: []string{"req", "body"}}, Pos: pos(2),
		}},
		FilesSeen: 1, FilesParsed: 1,
	}
	paths := prototypePollutionPathsForTest(t, doc)
	if len(paths) != 0 {
		t.Fatalf("generic application merge must not be a prototype-pollution sink: %#v", paths)
	}
}

func prototypePollutionPathsForTest(t *testing.T, doc jsprogram.Document) []JSTaintPath {
	t.Helper()
	resolution, err := jsprogram.Resolve(doc)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := BuildJSValueGraph(doc, resolution, DefaultJSCatalog())
	if err != nil {
		t.Fatal(err)
	}
	return JSPrototypePollutionPaths(doc, resolution, DefaultJSCatalog(), graph)
}

func jsPrototypePollutionDocument(module, alias string, defaultImport bool, callee []string) jsprogram.Document {
	pos := func(line int) jsprogram.Position { return jsprogram.Position{File: "app.js", Line: line} }
	moduleID := "app::<module>"
	return jsprogram.Document{
		SchemaVersion: jsprogram.SchemaVersion,
		Modules:       []jsprogram.Module{{Name: "app", File: "app.js", Pos: pos(1)}},
		Symbols:       []jsprogram.Symbol{{ID: moduleID, Module: "app", QualifiedName: "<module>", Name: "<module>", Kind: jsprogram.SymbolModule, Pos: pos(1)}},
		Imports: []jsprogram.Import{{
			ScopeID: moduleID, Module: module, Alias: alias, Default: defaultImport, Pos: pos(1),
		}},
		Calls: []jsprogram.Call{{
			ID: "merge-call", CallerID: moduleID,
			Callee: jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: callee},
			Arguments: []jsprogram.Argument{
				{Value: jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{"target"}}, Pos: pos(3)},
				{Value: jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: []string{"req", "body"}}, ValueID: "request", Pos: pos(3)},
			},
			Pos: pos(3),
		}},
		Values: []jsprogram.Value{{
			ID: "request", ScopeID: moduleID, Kind: jsprogram.ValueReference,
			Ref: jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: []string{"req", "body"}}, Pos: pos(2),
		}},
		FilesSeen: 1, FilesParsed: 1,
	}
}
