package taint

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
)

func TestJSValueFlowFindsExpressQueryToSQLSink(t *testing.T) {
	graph := buildJSTestGraph(t, jsTaintFixture(false))
	findings := graph.Vulnerabilities()
	var found bool
	for _, finding := range findings {
		if finding.Class == TaintSQL && finding.CWE == "CWE-89" && finding.Rule == "javascript-taint-sqli" {
			found = true
			if finding.SourceID != "request-value" || finding.CallID != "query-call" {
				t.Fatalf("unexpected witness: %#v", finding)
			}
		}
	}
	if !found {
		t.Fatalf("SQL taint finding missing: %#v", findings)
	}
}

func TestJSValueFlowClassSpecificSanitizerBlocksXSS(t *testing.T) {
	graph := buildJSTestGraph(t, jsTaintFixture(true))
	for _, finding := range graph.Vulnerabilities() {
		if finding.Class == TaintXSS && finding.CallID == "send-call" {
			t.Fatalf("DOMPurify.sanitize result reached XSS sink: %#v", finding)
		}
	}
}

func TestJSValueFlowSanitizerDoesNotEraseOtherClasses(t *testing.T) {
	graph := buildJSTestGraph(t, jsTaintFixture(true))
	var sql bool
	for _, finding := range graph.Vulnerabilities() {
		if finding.Class == TaintSQL && finding.CallID == "query-call" {
			sql = true
		}
	}
	if !sql {
		t.Fatal("HTML sanitizer incorrectly neutralized SQL taint")
	}
}

func TestJSValueFlowPropagatesArgumentParameterReturnAndCallResult(t *testing.T) {
	pos := func(line int) jsprogram.Position { return jsprogram.Position{File: "app.ts", Line: line} }
	moduleID := "app::<module>"
	helperID := "app::identity"
	handlerID := "app::handler"
	doc := jsprogram.Document{
		SchemaVersion: jsprogram.SchemaVersion,
		Modules: []jsprogram.Module{{Name: "app", File: "app.ts", Pos: pos(1)}},
		Symbols: []jsprogram.Symbol{
			{ID: moduleID, Module: "app", QualifiedName: "<module>", Name: "<module>", Kind: jsprogram.SymbolModule, Pos: pos(1)},
			{ID: helperID, Module: "app", QualifiedName: "identity", Name: "identity", ParentID: moduleID, Kind: jsprogram.SymbolFunction, Pos: pos(2), Parameters: []jsprogram.Parameter{{Name: "value", ValueID: "helper-param", Pos: pos(2)}}},
			{ID: handlerID, Module: "app", QualifiedName: "handler", Name: "handler", ParentID: moduleID, Kind: jsprogram.SymbolFunction, Pos: pos(5)},
		},
		Calls: []jsprogram.Call{
			{ID: "helper-call", CallerID: handlerID, Callee: jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{"identity"}}, Arguments: []jsprogram.Argument{{Value: jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: []string{"req", "query"}}, ValueID: "request-value", Pos: pos(6)}}, ResultID: "helper-result", Pos: pos(6)},
			{ID: "query-call", CallerID: handlerID, Callee: jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: []string{"db", "query"}}, Arguments: []jsprogram.Argument{{Value: jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{"safeish"}}, ValueID: "helper-result", Pos: pos(7)}}, Pos: pos(7)},
		},
		Returns: []jsprogram.Return{{ScopeID: helperID, Value: jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{"value"}}, ValueID: "helper-param", SlotID: "helper-return", Pos: pos(3)}},
		Values: []jsprogram.Value{
			{ID: "helper-param", ScopeID: helperID, Kind: jsprogram.ValueParameter, Name: "value", Ref: jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{"value"}}, Pos: pos(2)},
			{ID: "helper-return", ScopeID: helperID, Kind: jsprogram.ValueReturn, Ref: jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{"value"}}, Pos: pos(3)},
			{ID: "request-value", ScopeID: handlerID, Kind: jsprogram.ValueReference, Ref: jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: []string{"req", "query"}}, Pos: pos(6)},
			{ID: "helper-result", ScopeID: handlerID, Kind: jsprogram.ValueCallResult, Ref: jsprogram.Reference{Kind: jsprogram.ReferenceCall, Segments: []string{"identity"}}, Pos: pos(6)},
		},
		Flows: []jsprogram.ValueFlow{{FromID: "helper-param", ToID: "helper-return", Kind: jsprogram.FlowReturn, Pos: pos(3)}},
		FilesSeen: 1, FilesParsed: 1,
	}

	graph := buildJSTestGraph(t, doc)
	var sql *JSTaintPath
	for i := range graph.Vulnerabilities() {
		finding := graph.Vulnerabilities()[i]
		if finding.Class == TaintSQL && finding.CallID == "query-call" {
			sql = &finding
			break
		}
	}
	if sql == nil {
		t.Fatal("interprocedural request -> helper -> return -> SQL flow was not found")
	}
	seenParam, seenReturn := false, false
	for _, id := range sql.Path {
		seenParam = seenParam || id == "helper-param"
		seenReturn = seenReturn || id == "helper-return"
	}
	if !seenParam || !seenReturn {
		t.Fatalf("witness does not cross helper parameter/return: %#v", sql.Path)
	}
}

func buildJSTestGraph(t *testing.T, doc jsprogram.Document) JSValueFlowGraph {
	t.Helper()
	resolution, err := jsprogram.Resolve(doc)
	if err != nil { t.Fatal(err) }
	graph, err := BuildJSValueGraph(doc, resolution, DefaultJSCatalog())
	if err != nil { t.Fatal(err) }
	return graph
}

func jsTaintFixture(withSanitizer bool) jsprogram.Document {
	pos := func(line int) jsprogram.Position { return jsprogram.Position{File: "app.js", Line: line} }
	moduleID := "app::<module>"
	values := []jsprogram.Value{
		{ID: "request-value", ScopeID: moduleID, Kind: jsprogram.ValueReference, Ref: jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: []string{"req", "query"}}, Pos: pos(2)},
		{ID: "query-value", ScopeID: moduleID, Kind: jsprogram.ValueBinding, Name: "q", Ref: jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{"q"}}, Pos: pos(3)},
	}
	flows := []jsprogram.ValueFlow{{FromID: "request-value", ToID: "query-value", Kind: jsprogram.FlowAssignment, Pos: pos(3)}}
	calls := []jsprogram.Call{{
		ID: "query-call", CallerID: moduleID,
		Callee: jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: []string{"db", "query"}},
		Arguments: []jsprogram.Argument{{Value: jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{"q"}}, ValueID: "query-value", Pos: pos(4)}},
		Pos: pos(4),
	}}

	if withSanitizer {
		values = append(values, jsprogram.Value{ID: "clean-value", ScopeID: moduleID, Kind: jsprogram.ValueCallResult, Ref: jsprogram.Reference{Kind: jsprogram.ReferenceCall, Segments: []string{"DOMPurify", "sanitize"}}, Pos: pos(5)})
		flows = append(flows, jsprogram.ValueFlow{FromID: "query-value", ToID: "clean-value", Kind: jsprogram.FlowArgument, Pos: pos(5)})
		calls = append(calls,
			jsprogram.Call{ID: "sanitize-call", CallerID: moduleID, Callee: jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: []string{"DOMPurify", "sanitize"}}, Arguments: []jsprogram.Argument{{Value: jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{"q"}}, ValueID: "query-value", Pos: pos(5)}}, ResultID: "clean-value", Pos: pos(5)},
			jsprogram.Call{ID: "send-call", CallerID: moduleID, Callee: jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: []string{"res", "send"}}, Arguments: []jsprogram.Argument{{Value: jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{"clean"}}, ValueID: "clean-value", Pos: pos(6)}}, Pos: pos(6)},
		)
	} else {
		calls = append(calls, jsprogram.Call{ID: "send-call", CallerID: moduleID, Callee: jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: []string{"res", "send"}}, Arguments: []jsprogram.Argument{{Value: jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{"q"}}, ValueID: "query-value", Pos: pos(6)}}, Pos: pos(6)})
	}

	return jsprogram.Document{
		SchemaVersion: jsprogram.SchemaVersion,
		Modules: []jsprogram.Module{{Name: "app", File: "app.js", Pos: pos(1)}},
		Symbols: []jsprogram.Symbol{{ID: moduleID, Module: "app", QualifiedName: "<module>", Name: "<module>", Kind: jsprogram.SymbolModule, Pos: pos(1)}},
		Calls: calls, Values: values, Flows: flows,
		FilesSeen: 1, FilesParsed: 1,
	}
}
