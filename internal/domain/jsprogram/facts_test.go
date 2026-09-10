package jsprogram

import "testing"

func TestDocumentValidateAcceptsMinimalJavaScriptFacts(t *testing.T) {
	doc := minimalJSDocument()
	if err := doc.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !doc.Complete() {
		t.Fatal("minimal fully parsed document should be complete")
	}
}

func TestDocumentValidateAllowsOpaqueExpressionAndCallReferences(t *testing.T) {
	doc := minimalJSDocument()
	pos := Position{File: "app.js", Line: 2}
	doc.Values = []Value{{ID: "result", ScopeID: "app::<module>", Kind: ValueCallResult, Ref: Reference{Kind: ReferenceCall}, Pos: pos}}
	doc.Calls = []Call{{ID: "dynamic", CallerID: "app::<module>", Callee: Reference{Kind: ReferenceExpression}, ResultID: "result", Pos: pos}}
	doc.CoverageGaps = []CoverageGap{{Kind: GapUnresolvedCall, SymbolID: "app::<module>", Detail: "callee_shape", Pos: pos}}
	if err := doc.Validate(); err != nil {
		t.Fatalf("opaque dynamic shape should be structurally valid: %v", err)
	}
	if doc.Complete() {
		t.Fatal("dynamic shape with explicit gap cannot be complete")
	}
}

func TestDocumentValidateRejectsEscapingPosition(t *testing.T) {
	doc := Document{
		SchemaVersion: SchemaVersion,
		Modules: []Module{{Name: "app", File: "../app.js", Pos: Position{File: "../app.js", Line: 1}}},
		FilesSeen: 1, FilesParsed: 1,
	}
	if err := doc.Validate(); err == nil {
		t.Fatal("Validate() unexpectedly accepted an escaping path")
	}
}

func TestDocumentValidateRejectsDanglingValueFlow(t *testing.T) {
	doc := minimalJSDocument()
	pos := Position{File: "app.js", Line: 1}
	doc.Values = []Value{{ID: "v1", ScopeID: "app::<module>", Kind: ValueBinding, Ref: Reference{Kind: ReferenceName, Segments: []string{"x"}}, Pos: pos}}
	doc.Flows = []ValueFlow{{FromID: "v1", ToID: "missing", Kind: FlowAssignment, Pos: pos}}
	if err := doc.Validate(); err == nil {
		t.Fatal("Validate() unexpectedly accepted a dangling flow")
	}
}

func TestDocumentValidateRejectsDuplicateCallID(t *testing.T) {
	doc := minimalJSDocument()
	pos := Position{File: "app.js", Line: 2}
	call := Call{ID: "call", CallerID: "app::<module>", Callee: Reference{Kind: ReferenceName, Segments: []string{"fetch"}}, Pos: pos}
	doc.Calls = []Call{call, call}
	if err := doc.Validate(); err == nil {
		t.Fatal("Validate() unexpectedly accepted duplicate call IDs")
	}
}

func TestDocumentValidateRejectsDanglingParameterAndReceiver(t *testing.T) {
	t.Run("parameter", func(t *testing.T) {
		doc := minimalJSDocument()
		doc.Symbols = append(doc.Symbols, Symbol{
			ID: "app::f", Module: "app", QualifiedName: "f", Name: "f", ParentID: "app::<module>", Kind: SymbolFunction,
			Pos: Position{File: "app.js", Line: 2}, Parameters: []Parameter{{Name: "x", ValueID: "missing", Pos: Position{File: "app.js", Line: 2}}},
		})
		if err := doc.Validate(); err == nil {
			t.Fatal("Validate() unexpectedly accepted dangling parameter value")
		}
	})
	t.Run("receiver", func(t *testing.T) {
		doc := minimalJSDocument()
		doc.Calls = []Call{{
			ID: "call", CallerID: "app::<module>", Callee: Reference{Kind: ReferenceMember, Segments: []string{"db", "query"}},
			ReceiverValueID: "missing", Pos: Position{File: "app.js", Line: 2},
		}}
		if err := doc.Validate(); err == nil {
			t.Fatal("Validate() unexpectedly accepted dangling receiver value")
		}
	})
}

func TestDocumentValidateRejectsInvalidReturnSlot(t *testing.T) {
	doc := minimalJSDocument()
	fnPos := Position{File: "app.js", Line: 2}
	doc.Symbols = append(doc.Symbols, Symbol{ID: "app::f", Module: "app", QualifiedName: "f", Name: "f", ParentID: "app::<module>", Kind: SymbolFunction, Pos: fnPos})
	doc.Values = []Value{
		{ID: "source", ScopeID: "app::f", Kind: ValueReference, Ref: Reference{Kind: ReferenceName, Segments: []string{"x"}}, Pos: Position{File: "app.js", Line: 3}},
		{ID: "slot", ScopeID: "app::f", Kind: ValueBinding, Name: "notReturn", Ref: Reference{Kind: ReferenceName, Segments: []string{"notReturn"}}, Pos: Position{File: "app.js", Line: 3}},
	}
	doc.Returns = []Return{{ScopeID: "app::f", Value: Reference{Kind: ReferenceName, Segments: []string{"x"}}, ValueID: "source", SlotID: "slot", Pos: Position{File: "app.js", Line: 3}}}
	if err := doc.Validate(); err == nil {
		t.Fatal("Validate() unexpectedly accepted a non-return slot")
	}
}

func TestDocumentCompleteRequiresNoCoverageGaps(t *testing.T) {
	doc := Document{
		SchemaVersion: SchemaVersion,
		FilesSeen: 1,
		FilesParsed: 1,
		CoverageGaps: []CoverageGap{{Kind: GapDynamicProperty, Detail: "computed_property", Pos: Position{File: "app.js", Line: 2}}},
	}
	if doc.Complete() {
		t.Fatal("document with a coverage gap must not be complete")
	}
}

func minimalJSDocument() Document {
	pos := Position{File: "app.js", Line: 1}
	return Document{
		SchemaVersion: SchemaVersion,
		Modules: []Module{{Name: "app", File: "app.js", Pos: pos}},
		Symbols: []Symbol{{ID: "app::<module>", Module: "app", QualifiedName: "<module>", Name: "<module>", Kind: SymbolModule, Pos: pos}},
		FilesSeen: 1, FilesParsed: 1,
	}
}
