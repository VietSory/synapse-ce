package jsprogram

import "testing"

func TestResolveLocalFunctionAndRelativeImport(t *testing.T) {
	pos := func(file string, line int) Position { return Position{File: file, Line: line} }
	doc := Document{
		SchemaVersion: SchemaVersion,
		Modules: []Module{
			{Name: "app", File: "src/app.ts", Pos: pos("src/app.ts", 1)},
			{Name: "lib", File: "src/lib.ts", Pos: pos("src/lib.ts", 1)},
		},
		Symbols: []Symbol{
			{ID: "app::<module>", Module: "app", QualifiedName: "<module>", Name: "<module>", Kind: SymbolModule, Pos: pos("src/app.ts", 1)},
			{ID: "app::handler", Module: "app", QualifiedName: "handler", Name: "handler", ParentID: "app::<module>", Kind: SymbolFunction, Pos: pos("src/app.ts", 2)},
			{ID: "lib::<module>", Module: "lib", QualifiedName: "<module>", Name: "<module>", Kind: SymbolModule, Pos: pos("src/lib.ts", 1)},
			{ID: "lib::clean", Module: "lib", QualifiedName: "clean", Name: "clean", ParentID: "lib::<module>", Kind: SymbolFunction, Pos: pos("src/lib.ts", 2)},
		},
		Imports: []Import{{ScopeID: "app::<module>", Module: "./lib", Name: "clean", Alias: "sanitize", Pos: pos("src/app.ts", 1)}},
		Calls: []Call{
			{ID: "local-call", CallerID: "app::<module>", Callee: Reference{Kind: ReferenceName, Segments: []string{"handler"}}, Pos: pos("src/app.ts", 5)},
			{ID: "import-call", CallerID: "app::handler", Callee: Reference{Kind: ReferenceName, Segments: []string{"sanitize"}}, Pos: pos("src/app.ts", 6)},
		},
		FilesSeen: 2, FilesParsed: 2,
	}

	resolution, err := Resolve(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !resolution.Complete {
		t.Fatalf("expected complete resolution, gaps=%#v", resolution.Gaps)
	}
	calls := map[string]ResolvedCall{}
	for _, call := range resolution.Calls { calls[call.CallID] = call }
	if got := calls["local-call"].LocalCallees; len(got) != 1 || got[0] != "app::handler" {
		t.Fatalf("local resolution = %#v", got)
	}
	if got := calls["import-call"].LocalCallees; len(got) != 1 || got[0] != "lib::clean" {
		t.Fatalf("relative import resolution = %#v", got)
	}
}

func TestResolveExternalNamedAndDefaultImportsCanonically(t *testing.T) {
	pos := func(line int) Position { return Position{File: "app.js", Line: line} }
	doc := Document{
		SchemaVersion: SchemaVersion,
		Modules: []Module{{Name: "app", File: "app.js", Pos: pos(1)}},
		Symbols: []Symbol{{ID: "app::<module>", Module: "app", QualifiedName: "<module>", Name: "<module>", Kind: SymbolModule, Pos: pos(1)}},
		Imports: []Import{
			{ScopeID: "app::<module>", Module: "child_process", Name: "exec", Alias: "run", Pos: pos(1)},
			{ScopeID: "app::<module>", Module: "axios", Alias: "http", Default: true, Pos: pos(2)},
		},
		Calls: []Call{
			{ID: "exec", CallerID: "app::<module>", Callee: Reference{Kind: ReferenceName, Segments: []string{"run"}}, Pos: pos(4)},
			{ID: "get", CallerID: "app::<module>", Callee: Reference{Kind: ReferenceMember, Segments: []string{"http", "get"}}, Pos: pos(5)},
			{ID: "builtin", CallerID: "app::<module>", Callee: Reference{Kind: ReferenceName, Segments: []string{"fetch"}}, Pos: pos(6)},
		},
		FilesSeen: 1, FilesParsed: 1,
	}

	resolution, err := Resolve(doc)
	if err != nil { t.Fatal(err) }
	if !resolution.Complete { t.Fatalf("unexpected gaps: %#v", resolution.Gaps) }
	got := map[string]string{}
	for _, call := range resolution.Calls {
		if len(call.ExternalCallees) == 1 { got[call.CallID] = call.ExternalCallees[0] }
	}
	want := map[string]string{"exec": "child_process.exec", "get": "axios.get", "builtin": "global.fetch"}
	for id, expected := range want {
		if got[id] != expected { t.Fatalf("%s: got %q want %q", id, got[id], expected) }
	}
}

func TestResolveUnknownReceiverKeepsPositiveOnlyCoverage(t *testing.T) {
	pos := func(line int) Position { return Position{File: "app.js", Line: line} }
	doc := Document{
		SchemaVersion: SchemaVersion,
		Modules: []Module{{Name: "app", File: "app.js", Pos: pos(1)}},
		Symbols: []Symbol{{ID: "app::<module>", Module: "app", QualifiedName: "<module>", Name: "<module>", Kind: SymbolModule, Pos: pos(1)}},
		Calls: []Call{{ID: "send", CallerID: "app::<module>", Callee: Reference{Kind: ReferenceMember, Segments: []string{"res", "send"}}, Pos: pos(2)}},
		FilesSeen: 1, FilesParsed: 1,
	}
	resolution, err := Resolve(doc)
	if err != nil { t.Fatal(err) }
	if resolution.Complete { t.Fatal("unresolved receiver must make negative coverage incomplete") }
	if len(resolution.Gaps) != 1 || resolution.Gaps[0].Kind != GapUnresolvedCall {
		t.Fatalf("unexpected gaps: %#v", resolution.Gaps)
	}
}
