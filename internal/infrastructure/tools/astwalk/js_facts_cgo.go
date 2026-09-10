//go:build cgo

package astwalk

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
	tsxgrammar "github.com/smacker/go-tree-sitter/typescript/tsx"
	tsgrammar "github.com/smacker/go-tree-sitter/typescript/typescript"
)

const (
	maxJSFactNodes = 2_000_000
	maxJSFacts     = 4_000_000
)

// JSFactsFor extracts bounded JavaScript, TypeScript and TSX semantic facts without executing target
// code, package managers, module loaders, decorators, or build steps. Unsupported dynamic shapes are
// explicit coverage gaps: positive source-to-sink evidence remains usable, while negatives stay unsafe.
func JSFactsFor(ctx context.Context, root string) (jsprogram.Document, error) {
	doc := jsprogram.Document{SchemaVersion: jsprogram.SchemaVersion}
	modules := map[string]bool{}
	walkTruncated, err := walkJSSourceWithIssues(ctx, root, func(rel, lang string, content []byte) {
		doc.FilesSeen++
		rel = filepath.ToSlash(rel)
		module := jsModuleName(rel)
		if module == "" || modules[module] {
			doc.CoverageGaps = append(doc.CoverageGaps, jsprogram.CoverageGap{
				Kind: jsprogram.GapModuleResolution, Detail: "ambiguous_module_path", Pos: jsprogram.Position{File: rel, Line: 1},
			})
			return
		}
		modules[module] = true
		sp := spec{lang: javascript.GetLanguage()}
		if lang == "TypeScript" {
			if strings.EqualFold(filepath.Ext(rel), ".tsx") {
				sp.lang = tsxgrammar.GetLanguage()
			} else {
				sp.lang = tsgrammar.GetLanguage()
			}
		}
		rootNode := parseRoot(ctx, sp, content)
		if rootNode == nil {
			doc.CoverageGaps = append(doc.CoverageGaps, jsprogram.CoverageGap{
				Kind: jsprogram.GapParseRecovery, Detail: "parse_failed", Pos: jsprogram.Position{File: rel, Line: 1},
			})
			return
		}
		doc.FilesParsed++
		moduleID := jsSymbolID(module, "<module>")
		doc.Modules = append(doc.Modules, jsprogram.Module{Name: module, File: rel, Pos: jsprogram.Position{File: rel, Line: 1}})
		doc.Symbols = append(doc.Symbols, jsprogram.Symbol{
			ID: moduleID, Module: module, QualifiedName: "<module>", Name: "<module>", Kind: jsprogram.SymbolModule,
			Pos: jsprogram.Position{File: rel, Line: 1},
		})
		extractor := jsFactExtractor{
			doc: &doc, module: module, file: rel, source: content,
			values: map[string]bool{}, flows: map[string]bool{}, calls: map[string]bool{}, symbols: map[string]bool{moduleID: true},
		}
		if rootNode.HasError() {
			extractor.gap(jsprogram.GapParseRecovery, moduleID, "parser_recovery", rootNode)
		}
		extractor.walk(rootNode, jsScope{id: moduleID, qualified: "", kind: jsprogram.SymbolModule})
	}, func(issue sourceIssue) {
		doc.FilesSeen++
		kind := jsprogram.GapUnreadable
		if issue.Reason == sourceIssueOversized { kind = jsprogram.GapBudget }
		doc.CoverageGaps = append(doc.CoverageGaps, jsprogram.CoverageGap{
			Kind: kind, Detail: string(issue.Reason), Pos: jsprogram.Position{File: filepath.ToSlash(issue.Rel), Line: 1},
		})
	})
	if err != nil { return jsprogram.Document{}, err }
	if walkTruncated { doc.Truncated = true }
	sortJSDocument(&doc)
	if err := doc.Validate(); err != nil {
		return jsprogram.Document{}, fmt.Errorf("validate extracted javascript facts: %w", err)
	}
	return doc, nil
}

type jsScope struct {
	id        string
	qualified string
	kind      jsprogram.SymbolKind
}

type jsFactExtractor struct {
	doc       *jsprogram.Document
	module    string
	file      string
	source    []byte
	budgetHit bool
	values    map[string]bool
	flows     map[string]bool
	calls     map[string]bool
	symbols   map[string]bool
}

func (e *jsFactExtractor) walk(node *sitter.Node, scope jsScope) {
	if node == nil || e.budgetHit { return }
	e.doc.NodesSeen++
	if e.doc.NodesSeen > maxJSFactNodes || e.factCount() > maxJSFacts {
		e.doc.Truncated = true
		e.budgetHit = true
		e.gap(jsprogram.GapBudget, scope.id, "node_or_fact_budget", node)
		return
	}
	switch node.Type() {
	case "function_declaration", "generator_function_declaration":
		e.walkFunction(node, scope, "", jsprogram.SymbolFunction)
		return
	case "class_declaration":
		e.walkClass(node, scope, "")
		return
	case "method_definition":
		e.walkFunction(node, scope, "", jsprogram.SymbolMethod)
		return
	case "import_statement":
		e.importFacts(node, scope)
		return
	case "variable_declarator":
		e.variableFact(node, scope)
		return
	case "assignment_expression", "augmented_assignment_expression":
		e.assignmentFact(node, scope)
		return
	case "return_statement":
		e.returnFact(node, scope)
		return
	case "call_expression", "new_expression":
		e.expressionValue(node, scope)
		return
	}
	for i := 0; i < int(node.NamedChildCount()); i++ { e.walk(node.NamedChild(i), scope) }
}

func (e *jsFactExtractor) walkFunction(node *sitter.Node, parent jsScope, nameHint string, forced jsprogram.SymbolKind) string {
	name := nameHint
	if name == "" {
		if nameNode := node.ChildByFieldName("name"); nameNode != nil { name = strings.TrimSpace(nameNode.Content(e.source)) }
	}
	if name == "" { name = fmt.Sprintf("<anonymous@%d:%d>", node.StartPoint().Row+1, node.StartPoint().Column) }
	qualified := joinJSQualified(parent.qualified, name)
	id := jsSymbolID(e.module, qualified)
	if e.symbols[id] { return id }
	kind := forced
	if kind == "" {
		kind = jsprogram.SymbolFunction
		if parent.kind == jsprogram.SymbolClass { kind = jsprogram.SymbolMethod }
		if node.Type() == "arrow_function" { kind = jsprogram.SymbolArrow }
	}
	params := e.parameters(node.ChildByFieldName("parameters"), id)
	if node.Type() == "arrow_function" && node.ChildByFieldName("parameters") == nil {
		if p := node.ChildByFieldName("parameter"); p != nil { params = e.parameters(p, id) }
	}
	e.doc.Symbols = append(e.doc.Symbols, jsprogram.Symbol{
		ID: id, Module: e.module, QualifiedName: qualified, Name: name, ParentID: parent.id,
		Kind: kind, Pos: e.position(node), Parameters: params, Async: nodeHasToken(node, "async"),
	})
	e.symbols[id] = true
	body := node.ChildByFieldName("body")
	if body != nil {
		e.walk(body, jsScope{id: id, qualified: qualified, kind: kind})
	}
	return id
}

func (e *jsFactExtractor) walkClass(node *sitter.Node, parent jsScope, nameHint string) string {
	name := nameHint
	if name == "" {
		if nameNode := node.ChildByFieldName("name"); nameNode != nil { name = strings.TrimSpace(nameNode.Content(e.source)) }
	}
	if name == "" { name = fmt.Sprintf("<class@%d:%d>", node.StartPoint().Row+1, node.StartPoint().Column) }
	qualified := joinJSQualified(parent.qualified, name)
	id := jsSymbolID(e.module, qualified)
	if e.symbols[id] { return id }
	e.doc.Symbols = append(e.doc.Symbols, jsprogram.Symbol{
		ID: id, Module: e.module, QualifiedName: qualified, Name: name, ParentID: parent.id,
		Kind: jsprogram.SymbolClass, Pos: e.position(node),
	})
	e.symbols[id] = true
	if body := node.ChildByFieldName("body"); body != nil {
		e.walk(body, jsScope{id: id, qualified: qualified, kind: jsprogram.SymbolClass})
	}
	return id
}

func (e *jsFactExtractor) parameters(node *sitter.Node, scopeID string) []jsprogram.Parameter {
	if node == nil { return nil }
	var candidates []*sitter.Node
	if node.Type() == "identifier" || node.Type() == "required_parameter" || node.Type() == "optional_parameter" || node.Type() == "rest_pattern" || node.Type() == "assignment_pattern" {
		candidates = append(candidates, node)
	} else {
		for i := 0; i < int(node.NamedChildCount()); i++ { candidates = append(candidates, node.NamedChild(i)) }
	}
	var out []jsprogram.Parameter
	for _, candidate := range candidates {
		rest := candidate.Type() == "rest_pattern"
		nameNode := jsParameterNameNode(candidate)
		if nameNode == nil {
			e.gap(jsprogram.GapUnresolvedValue, scopeID, "destructured_parameter", candidate)
			continue
		}
		name := strings.TrimSpace(nameNode.Content(e.source))
		if name == "" { continue }
		id := e.ensureValue(nameNode, scopeID, jsprogram.ValueParameter, name, jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{name}})
		out = append(out, jsprogram.Parameter{Name: name, ValueID: id, Pos: e.position(nameNode), Rest: rest})
	}
	return out
}

func jsParameterNameNode(node *sitter.Node) *sitter.Node {
	if node == nil { return nil }
	if node.Type() == "identifier" { return node }
	for _, field := range []string{"pattern", "name", "left"} {
		if child := node.ChildByFieldName(field); child != nil {
			if found := jsParameterNameNode(child); found != nil { return found }
		}
	}
	if node.Type() == "rest_pattern" || node.Type() == "assignment_pattern" || node.Type() == "required_parameter" || node.Type() == "optional_parameter" {
		for i := 0; i < int(node.NamedChildCount()); i++ {
			if found := jsParameterNameNode(node.NamedChild(i)); found != nil { return found }
		}
	}
	return nil
}

func (e *jsFactExtractor) importFacts(node *sitter.Node, scope jsScope) {
	sourceNode := node.ChildByFieldName("source")
	module, ok := e.staticString(sourceNode)
	if !ok {
		e.gap(jsprogram.GapDynamicImport, scope.id, "dynamic_import", node)
		return
	}
	clause := node.ChildByFieldName("import")
	if clause == nil {
		for i := 0; i < int(node.NamedChildCount()); i++ {
			child := node.NamedChild(i)
			if child == sourceNode { continue }
			if child.Type() == "import_clause" { clause = child; break }
		}
	}
	if clause == nil { return } // side-effect-only import
	e.extractImportBindings(clause, scope.id, module)
}

func (e *jsFactExtractor) extractImportBindings(node *sitter.Node, scopeID, module string) {
	if node == nil { return }
	switch node.Type() {
	case "identifier":
		alias := strings.TrimSpace(node.Content(e.source))
		if alias != "" { e.doc.Imports = append(e.doc.Imports, jsprogram.Import{ScopeID: scopeID, Module: module, Alias: alias, Default: true, Pos: e.position(node)}) }
		return
	case "namespace_import":
		name := lastIdentifier(node, e.source)
		if name != "" { e.doc.Imports = append(e.doc.Imports, jsprogram.Import{ScopeID: scopeID, Module: module, Alias: name, Star: true, Pos: e.position(node)}) }
		return
	case "import_specifier":
		nameNode := node.ChildByFieldName("name")
		aliasNode := node.ChildByFieldName("alias")
		if nameNode == nil && node.NamedChildCount() > 0 { nameNode = node.NamedChild(0) }
		if nameNode == nil { return }
		name := strings.TrimSpace(nameNode.Content(e.source))
		alias := name
		if aliasNode != nil { alias = strings.TrimSpace(aliasNode.Content(e.source)) }
		if name != "" && alias != "" { e.doc.Imports = append(e.doc.Imports, jsprogram.Import{ScopeID: scopeID, Module: module, Name: name, Alias: alias, Pos: e.position(node)}) }
		return
	}
	for i := 0; i < int(node.NamedChildCount()); i++ { e.extractImportBindings(node.NamedChild(i), scopeID, module) }
}

func (e *jsFactExtractor) variableFact(node *sitter.Node, scope jsScope) {
	left := node.ChildByFieldName("name")
	right := node.ChildByFieldName("value")
	if left == nil && node.NamedChildCount() > 0 { left = node.NamedChild(0) }
	if right == nil && node.NamedChildCount() > 1 { right = node.NamedChild(1) }
	if left == nil { return }
	nameHint := simpleJSBindingName(left, e.source)
	if right != nil {
		switch right.Type() {
		case "arrow_function", "function", "function_expression", "generator_function":
			e.walkFunction(right, scope, nameHint, "")
			return
		case "class", "class_expression":
			e.walkClass(right, scope, nameHint)
			return
		}
		if e.commonJSImport(left, right, scope.id) { return }
	}
	var rightID string
	if right != nil { rightID = e.expressionValue(right, scope) }
	e.bindTarget(left, rightID, scope)
}

func (e *jsFactExtractor) commonJSImport(left, right *sitter.Node, scopeID string) bool {
	if right == nil || right.Type() != "call_expression" { return false }
	callee := right.ChildByFieldName("function")
	if callee == nil || callee.Type() != "identifier" || callee.Content(e.source) != "require" { return false }
	args := right.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() != 1 {
		e.gap(jsprogram.GapDynamicImport, scopeID, "dynamic_require", right)
		return true
	}
	module, ok := e.staticString(args.NamedChild(0))
	if !ok {
		e.gap(jsprogram.GapDynamicImport, scopeID, "dynamic_require", right)
		return true
	}
	if left.Type() == "identifier" {
		alias := strings.TrimSpace(left.Content(e.source))
		e.doc.Imports = append(e.doc.Imports, jsprogram.Import{ScopeID: scopeID, Module: module, Alias: alias, Star: true, Pos: e.position(left)})
		return true
	}
	if left.Type() == "object_pattern" {
		for i := 0; i < int(left.NamedChildCount()); i++ {
			child := left.NamedChild(i)
			name, alias := destructuredBinding(child, e.source)
			if name != "" && alias != "" {
				e.doc.Imports = append(e.doc.Imports, jsprogram.Import{ScopeID: scopeID, Module: module, Name: name, Alias: alias, Pos: e.position(child)})
			}
		}
		return true
	}
	return false
}

func destructuredBinding(node *sitter.Node, source []byte) (string, string) {
	if node == nil { return "", "" }
	if node.Type() == "shorthand_property_identifier_pattern" || node.Type() == "identifier" {
		name := strings.TrimSpace(node.Content(source)); return name, name
	}
	if node.Type() == "pair_pattern" || node.Type() == "pair" {
		key := node.ChildByFieldName("key")
		value := node.ChildByFieldName("value")
		if key != nil && value != nil {
			return strings.TrimSpace(key.Content(source)), strings.TrimSpace(value.Content(source))
		}
	}
	return "", ""
}

func (e *jsFactExtractor) assignmentFact(node *sitter.Node, scope jsScope) string {
	left := node.ChildByFieldName("left")
	right := node.ChildByFieldName("right")
	if left == nil && node.NamedChildCount() > 0 { left = node.NamedChild(0) }
	if right == nil && node.NamedChildCount() > 1 { right = node.NamedChild(int(node.NamedChildCount())-1) }
	if left == nil || right == nil { return "" }
	rightID := e.expressionValue(right, scope)
	if node.Type() == "augmented_assignment_expression" {
		if old := e.expressionValue(left, scope); old != "" && rightID != "" {
			merged := e.ensureValue(node, scope.id, jsprogram.ValueExpression, "", jsprogram.Reference{Kind: jsprogram.ReferenceExpression})
			e.addFlow(old, merged, jsprogram.FlowExpression, node)
			e.addFlow(rightID, merged, jsprogram.FlowExpression, node)
			rightID = merged
		}
	}
	return e.bindTarget(left, rightID, scope)
}

func (e *jsFactExtractor) bindTarget(left *sitter.Node, rightID string, scope jsScope) string {
	if left == nil { return "" }
	if left.Type() == "identifier" {
		name := strings.TrimSpace(left.Content(e.source))
		ref := jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{name}}
		id := e.ensureValue(left, scope.id, jsprogram.ValueBinding, name, ref)
		if rightID != "" { e.addFlow(rightID, id, jsprogram.FlowAssignment, left) }
		e.doc.Assignments = append(e.doc.Assignments, jsprogram.Assignment{ScopeID: scope.id, Targets: []jsprogram.Reference{ref}, TargetIDs: []string{id}, ValueID: rightID, Pos: e.position(left)})
		return id
	}
	if left.Type() == "member_expression" || left.Type() == "subscript_expression" {
		ref := e.reference(left, scope)
		id := e.ensureValue(left, scope.id, jsprogram.ValueProperty, lastSegment(ref), ref)
		if rightID != "" { e.addFlow(rightID, id, jsprogram.FlowAssignment, left) }
		e.doc.Assignments = append(e.doc.Assignments, jsprogram.Assignment{ScopeID: scope.id, Targets: []jsprogram.Reference{ref}, TargetIDs: []string{id}, ValueID: rightID, Pos: e.position(left)})
		return id
	}
	if left.Type() == "object_pattern" || left.Type() == "array_pattern" {
		e.gap(jsprogram.GapUnresolvedValue, scope.id, "destructuring_assignment", left)
		var last string
		for i := 0; i < int(left.NamedChildCount()); i++ {
			child := left.NamedChild(i)
			name := simpleJSBindingName(child, e.source)
			if name == "" { continue }
			last = e.bindTarget(findIdentifier(child), rightID, scope)
		}
		return last
	}
	e.gap(jsprogram.GapUnresolvedValue, scope.id, "assignment_target", left)
	return ""
}

func (e *jsFactExtractor) returnFact(node *sitter.Node, scope jsScope) {
	if scope.kind == jsprogram.SymbolModule || scope.kind == jsprogram.SymbolClass { return }
	var valueNode *sitter.Node
	if node.NamedChildCount() > 0 { valueNode = node.NamedChild(0) }
	if valueNode == nil { return }
	valueID := e.expressionValue(valueNode, scope)
	ref := e.reference(valueNode, scope)
	slotID := e.ensureValue(node, scope.id, jsprogram.ValueReturn, "", ref)
	e.addFlow(valueID, slotID, jsprogram.FlowReturn, node)
	e.doc.Returns = append(e.doc.Returns, jsprogram.Return{ScopeID: scope.id, Value: ref, ValueID: valueID, SlotID: slotID, Pos: e.position(node)})
}

func (e *jsFactExtractor) expressionValue(node *sitter.Node, scope jsScope) string {
	if node == nil || e.budgetHit { return "" }
	switch node.Type() {
	case "identifier", "this", "shorthand_property_identifier":
		ref := e.reference(node, scope)
		return e.ensureValue(node, scope.id, jsprogram.ValueReference, lastSegment(ref), ref)
	case "member_expression", "subscript_expression":
		ref := e.reference(node, scope)
		id := e.ensureValue(node, scope.id, jsprogram.ValueReference, lastSegment(ref), ref)
		object := node.ChildByFieldName("object")
		if object != nil {
			if objectID := e.expressionValue(object, scope); objectID != "" { e.addFlow(objectID, id, jsprogram.FlowMember, node) }
		}
		return id
	case "call_expression", "new_expression":
		return e.callFact(node, scope)
	case "assignment_expression", "augmented_assignment_expression":
		return e.assignmentFact(node, scope)
	case "parenthesized_expression", "await_expression":
		if node.NamedChildCount() > 0 { return e.expressionValue(node.NamedChild(0), scope) }
	case "string", "number", "true", "false", "null", "undefined", "regex":
		return e.ensureValue(node, scope.id, jsprogram.ValueLiteral, "", jsprogram.Reference{Kind: jsprogram.ReferenceLiteral})
	case "template_string":
		if node.NamedChildCount() == 0 { return e.ensureValue(node, scope.id, jsprogram.ValueLiteral, "", jsprogram.Reference{Kind: jsprogram.ReferenceLiteral}) }
	}
	id := e.ensureValue(node, scope.id, jsprogram.ValueExpression, "", jsprogram.Reference{Kind: jsprogram.ReferenceExpression})
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		if isTypeOnlyJSNode(child.Type()) { continue }
		childID := e.expressionValue(child, scope)
		if childID != "" { e.addFlow(childID, id, jsprogram.FlowExpression, child) }
	}
	return id
}

func (e *jsFactExtractor) callFact(node *sitter.Node, scope jsScope) string {
	id := e.callID(node)
	if e.calls[id] {
		return e.ensureValue(node, scope.id, jsprogram.ValueCallResult, "", jsprogram.Reference{Kind: jsprogram.ReferenceCall})
	}
	calleeNode := node.ChildByFieldName("function")
	if calleeNode == nil { calleeNode = node.ChildByFieldName("constructor") }
	if calleeNode == nil && node.NamedChildCount() > 0 { calleeNode = node.NamedChild(0) }
	callee := e.reference(calleeNode, scope)
	if callee.Kind == jsprogram.ReferenceUnknown {
		e.gap(jsprogram.GapUnresolvedCall, scope.id, "callee_shape", node)
	}
	resultID := e.ensureValue(node, scope.id, jsprogram.ValueCallResult, "", jsprogram.Reference{Kind: jsprogram.ReferenceCall, Segments: append([]string(nil), callee.Segments...)})
	var receiverID string
	if calleeNode != nil && (calleeNode.Type() == "member_expression" || calleeNode.Type() == "subscript_expression") {
		if object := calleeNode.ChildByFieldName("object"); object != nil { receiverID = e.expressionValue(object, scope) }
	}
	var args []jsprogram.Argument
	arguments := node.ChildByFieldName("arguments")
	if arguments != nil {
		for i := 0; i < int(arguments.NamedChildCount()); i++ {
			argNode := arguments.NamedChild(i)
			spread := argNode.Type() == "spread_element"
			valueNode := argNode
			if spread && argNode.NamedChildCount() > 0 { valueNode = argNode.NamedChild(0) }
			valueID := e.expressionValue(valueNode, scope)
			args = append(args, jsprogram.Argument{Value: e.reference(valueNode, scope), ValueID: valueID, Pos: e.position(argNode), Spread: spread})
		}
	}
	e.doc.Calls = append(e.doc.Calls, jsprogram.Call{
		ID: id, CallerID: scope.id, Callee: callee, Arguments: args, ResultID: resultID,
		ReceiverValueID: receiverID, Pos: e.position(node), Constructor: node.Type() == "new_expression",
	})
	e.calls[id] = true
	return resultID
}

func (e *jsFactExtractor) reference(node *sitter.Node, scope jsScope) jsprogram.Reference {
	if node == nil { return jsprogram.Reference{Kind: jsprogram.ReferenceUnknown} }
	switch node.Type() {
	case "identifier", "property_identifier", "shorthand_property_identifier", "this":
		value := strings.TrimSpace(node.Content(e.source))
		if value != "" { return jsprogram.Reference{Kind: jsprogram.ReferenceName, Segments: []string{value}} }
	case "member_expression":
		object := node.ChildByFieldName("object")
		property := node.ChildByFieldName("property")
		left := e.reference(object, scope)
		if property == nil || len(left.Segments) == 0 { return jsprogram.Reference{Kind: jsprogram.ReferenceUnknown} }
		name := strings.TrimSpace(property.Content(e.source))
		if name == "" { return jsprogram.Reference{Kind: jsprogram.ReferenceUnknown} }
		return jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: append(append([]string(nil), left.Segments...), name)}
	case "subscript_expression":
		object := node.ChildByFieldName("object")
		index := node.ChildByFieldName("index")
		left := e.reference(object, scope)
		name, ok := e.staticString(index)
		if !ok || len(left.Segments) == 0 {
			e.gap(jsprogram.GapDynamicProperty, scope.id, "computed_property", node)
			return jsprogram.Reference{Kind: jsprogram.ReferenceUnknown}
		}
		return jsprogram.Reference{Kind: jsprogram.ReferenceMember, Segments: append(append([]string(nil), left.Segments...), name)}
	case "call_expression", "new_expression":
		callee := node.ChildByFieldName("function")
		if callee == nil { callee = node.ChildByFieldName("constructor") }
		ref := e.reference(callee, scope)
		return jsprogram.Reference{Kind: jsprogram.ReferenceCall, Segments: append([]string(nil), ref.Segments...)}
	case "parenthesized_expression", "await_expression", "non_null_expression", "as_expression":
		if node.NamedChildCount() > 0 { return e.reference(node.NamedChild(0), scope) }
	case "string", "number", "true", "false", "null", "undefined", "template_string":
		return jsprogram.Reference{Kind: jsprogram.ReferenceLiteral}
	}
	return jsprogram.Reference{Kind: jsprogram.ReferenceExpression}
}

func (e *jsFactExtractor) ensureValue(node *sitter.Node, scopeID string, kind jsprogram.ValueKind, name string, ref jsprogram.Reference) string {
	if node == nil || scopeID == "" { return "" }
	id := e.valueID(node, kind)
	if e.values[id] { return id }
	if len(e.doc.Values) >= maxJSFacts { e.doc.Truncated = true; e.budgetHit = true; return "" }
	e.doc.Values = append(e.doc.Values, jsprogram.Value{ID: id, ScopeID: scopeID, Kind: kind, Name: name, Ref: ref, Pos: e.position(node)})
	e.values[id] = true
	return id
}

func (e *jsFactExtractor) addFlow(from, to string, kind jsprogram.ValueFlowKind, node *sitter.Node) {
	if from == "" || to == "" || from == to || e.budgetHit { return }
	key := from + "\x00" + to + "\x00" + string(kind)
	if e.flows[key] { return }
	if len(e.doc.Flows) >= maxJSFacts { e.doc.Truncated = true; e.budgetHit = true; return }
	e.doc.Flows = append(e.doc.Flows, jsprogram.ValueFlow{FromID: from, ToID: to, Kind: kind, Pos: e.position(node)})
	e.flows[key] = true
}

func (e *jsFactExtractor) gap(kind jsprogram.GapKind, scopeID, detail string, node *sitter.Node) {
	if node == nil { return }
	e.doc.CoverageGaps = append(e.doc.CoverageGaps, jsprogram.CoverageGap{Kind: kind, SymbolID: scopeID, Detail: detail, Pos: e.position(node)})
}

func (e *jsFactExtractor) position(node *sitter.Node) jsprogram.Position {
	if node == nil { return jsprogram.Position{File: e.file, Line: 1} }
	return jsprogram.Position{File: e.file, Line: int(node.StartPoint().Row) + 1, Column: int(node.StartPoint().Column)}
}

func (e *jsFactExtractor) valueID(node *sitter.Node, kind jsprogram.ValueKind) string {
	return fmt.Sprintf("jsv:%s:%d:%d:%s", e.file, node.StartByte(), node.EndByte(), kind)
}

func (e *jsFactExtractor) callID(node *sitter.Node) string {
	return fmt.Sprintf("jsc:%s:%d:%d", e.file, node.StartByte(), node.EndByte())
}

func (e *jsFactExtractor) staticString(node *sitter.Node) (string, bool) {
	if node == nil || node.Type() != "string" { return "", false }
	raw := strings.TrimSpace(node.Content(e.source))
	if len(raw) < 2 { return "", false }
	quote := raw[0]
	if (quote != '\'' && quote != '"') || raw[len(raw)-1] != quote { return "", false }
	value := raw[1:len(raw)-1]
	if strings.Contains(value, "\\") { return "", false }
	return value, value != ""
}

func (e *jsFactExtractor) factCount() int {
	return len(e.doc.Symbols)+len(e.doc.Imports)+len(e.doc.Calls)+len(e.doc.Assignments)+len(e.doc.Returns)+len(e.doc.Values)+len(e.doc.Flows)+len(e.doc.CoverageGaps)
}

func jsModuleName(rel string) string {
	clean := filepath.ToSlash(strings.TrimPrefix(rel, "./"))
	if clean == "" { return "" }
	for _, ext := range []string{".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"} {
		if strings.HasSuffix(strings.ToLower(clean), ext) { return clean[:len(clean)-len(ext)] }
	}
	return ""
}

func jsSymbolID(module, qualified string) string { return "javascript:" + module + ":" + qualified }

func joinJSQualified(parent, name string) string {
	if parent == "" { return name }
	return parent + "." + name
}

func simpleJSBindingName(node *sitter.Node, source []byte) string {
	id := findIdentifier(node)
	if id == nil { return "" }
	return strings.TrimSpace(id.Content(source))
}

func findIdentifier(node *sitter.Node) *sitter.Node {
	if node == nil { return nil }
	if node.Type() == "identifier" || node.Type() == "shorthand_property_identifier_pattern" { return node }
	for i := 0; i < int(node.NamedChildCount()); i++ {
		if found := findIdentifier(node.NamedChild(i)); found != nil { return found }
	}
	return nil
}

func lastIdentifier(node *sitter.Node, source []byte) string {
	if node == nil { return "" }
	var last string
	var walk func(*sitter.Node)
	walk = func(current *sitter.Node) {
		if current == nil { return }
		if current.Type() == "identifier" { last = strings.TrimSpace(current.Content(source)) }
		for i := 0; i < int(current.NamedChildCount()); i++ { walk(current.NamedChild(i)) }
	}
	walk(node)
	return last
}

func lastSegment(ref jsprogram.Reference) string {
	if len(ref.Segments) == 0 { return "" }
	return ref.Segments[len(ref.Segments)-1]
}

func nodeHasToken(node *sitter.Node, token string) bool {
	if node == nil { return false }
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil && child.Type() == token { return true }
	}
	return false
}

func isTypeOnlyJSNode(kind string) bool {
	switch kind {
	case "type_annotation", "type_arguments", "type_parameters", "predefined_type", "interface_declaration", "type_alias_declaration":
		return true
	}
	return false
}

func sortJSDocument(doc *jsprogram.Document) {
	positionLess := func(a, b jsprogram.Position) bool {
		if a.File != b.File { return a.File < b.File }
		if a.Line != b.Line { return a.Line < b.Line }
		return a.Column < b.Column
	}
	sort.Slice(doc.Modules, func(i, j int) bool { return doc.Modules[i].Name < doc.Modules[j].Name })
	sort.Slice(doc.Symbols, func(i, j int) bool { return doc.Symbols[i].ID < doc.Symbols[j].ID })
	sort.Slice(doc.Imports, func(i, j int) bool {
		if doc.Imports[i].Module != doc.Imports[j].Module { return doc.Imports[i].Module < doc.Imports[j].Module }
		if doc.Imports[i].Alias != doc.Imports[j].Alias { return doc.Imports[i].Alias < doc.Imports[j].Alias }
		return doc.Imports[i].Name < doc.Imports[j].Name
	})
	sort.Slice(doc.Calls, func(i, j int) bool { return doc.Calls[i].ID < doc.Calls[j].ID })
	sort.Slice(doc.Assignments, func(i, j int) bool { return positionLess(doc.Assignments[i].Pos, doc.Assignments[j].Pos) })
	sort.Slice(doc.Returns, func(i, j int) bool { return positionLess(doc.Returns[i].Pos, doc.Returns[j].Pos) })
	sort.Slice(doc.Values, func(i, j int) bool { return doc.Values[i].ID < doc.Values[j].ID })
	sort.Slice(doc.Flows, func(i, j int) bool {
		if doc.Flows[i].FromID != doc.Flows[j].FromID { return doc.Flows[i].FromID < doc.Flows[j].FromID }
		if doc.Flows[i].ToID != doc.Flows[j].ToID { return doc.Flows[i].ToID < doc.Flows[j].ToID }
		return doc.Flows[i].Kind < doc.Flows[j].Kind
	})
	sort.Slice(doc.CoverageGaps, func(i, j int) bool {
		if positionLess(doc.CoverageGaps[i].Pos, doc.CoverageGaps[j].Pos) { return true }
		if positionLess(doc.CoverageGaps[j].Pos, doc.CoverageGaps[i].Pos) { return false }
		if doc.CoverageGaps[i].Kind != doc.CoverageGaps[j].Kind { return doc.CoverageGaps[i].Kind < doc.CoverageGaps[j].Kind }
		return doc.CoverageGaps[i].Detail < doc.CoverageGaps[j].Detail
	})
}
