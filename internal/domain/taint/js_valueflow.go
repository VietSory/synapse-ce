package taint

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	maxJSValueEdges   = 4_000_000
	maxJSTaintSources = 200_000
	maxJSTaintSinks   = 1_000_000
	maxJSTaintWork    = 4_000_000
	maxJSTaintPath    = 64
)

type JSTypedSource struct {
	ValueID string
	Class   TaintClass
	Pos     jsprogram.Position
}

type JSTypedSink struct {
	ValueID string
	CallID  string
	Callee  string
	Class   TaintClass
	CWE     string
	Rule    string
	Pos     jsprogram.Position
}

type JSTypedSanitizer struct {
	ValueID string
	Class   TaintClass
}

type JSValueFlowGraph struct {
	Edges      map[string][]string
	Sources    []JSTypedSource
	Sinks      []JSTypedSink
	Sanitizers []JSTypedSanitizer
	Positions  map[string]jsprogram.Position
	Truncated  bool
}

type JSTaintPath struct {
	Class     TaintClass
	CWE       string
	Rule      string
	SourceID  string
	SinkID    string
	CallID    string
	Callee    string
	Path      []string
	SourcePos jsprogram.Position
	SinkPos   jsprogram.Position
}

// BuildJSValueGraph joins parser-emitted value facts with semantic call resolution. First-party
// calls get explicit argument->parameter and return->call-result edges; unresolved/external transforms
// conservatively propagate inputs into their result unless a reviewed source/sink model defines the role.
func BuildJSValueGraph(document jsprogram.Document, resolution jsprogram.Resolution, catalog JSCatalog) (JSValueFlowGraph, error) {
	if err := document.Validate(); err != nil {
		return JSValueFlowGraph{}, fmt.Errorf("build javascript value flow: %w", err)
	}
	if err := validateJSCatalog(catalog); err != nil {
		return JSValueFlowGraph{}, err
	}
	if err := validateJSResolution(document, resolution); err != nil {
		return JSValueFlowGraph{}, err
	}
	b := jsValueBuilder{
		document: document, resolution: resolution, catalog: catalog,
		values: map[string]jsprogram.Value{}, symbols: map[string]jsprogram.Symbol{}, parents: map[string]string{},
		children: map[string]map[string][]string{}, definitions: map[string]map[string][]jsprogram.Value{},
		returns: map[string][]string{}, calls: map[string]jsprogram.ResolvedCall{}, edgeSets: map[string]map[string]bool{},
		sources: map[string]JSTypedSource{}, sinks: map[string]JSTypedSink{}, sanitizers: map[string]JSTypedSanitizer{},
		positions: map[string]jsprogram.Position{},
	}
	b.index()
	b.addSyntaxFlows()
	b.bindReferences()
	b.modelCalls()
	b.modelReferenceSources()
	return b.finish(), nil
}

type jsValueBuilder struct {
	document    jsprogram.Document
	resolution  jsprogram.Resolution
	catalog     JSCatalog
	values      map[string]jsprogram.Value
	symbols     map[string]jsprogram.Symbol
	parents     map[string]string
	children    map[string]map[string][]string
	definitions map[string]map[string][]jsprogram.Value
	returns     map[string][]string
	calls       map[string]jsprogram.ResolvedCall
	edgeSets    map[string]map[string]bool
	sources     map[string]JSTypedSource
	sinks       map[string]JSTypedSink
	sanitizers  map[string]JSTypedSanitizer
	positions   map[string]jsprogram.Position
	edgeCount   int
	truncated   bool
}

func (b *jsValueBuilder) index() {
	for _, symbol := range b.document.Symbols {
		b.symbols[symbol.ID] = symbol
		b.parents[symbol.ID] = symbol.ParentID
		if symbol.ParentID != "" {
			if b.children[symbol.ParentID] == nil {
				b.children[symbol.ParentID] = map[string][]string{}
			}
			b.children[symbol.ParentID][symbol.Name] = append(b.children[symbol.ParentID][symbol.Name], symbol.ID)
		}
	}
	for _, value := range b.document.Values {
		b.values[value.ID] = value
		b.positions[value.ID] = value.Pos
		if (value.Kind == jsprogram.ValueParameter || value.Kind == jsprogram.ValueBinding) && value.Name != "" {
			if b.definitions[value.ScopeID] == nil {
				b.definitions[value.ScopeID] = map[string][]jsprogram.Value{}
			}
			b.definitions[value.ScopeID][value.Name] = append(b.definitions[value.ScopeID][value.Name], value)
		}
	}
	for scope := range b.definitions {
		for name := range b.definitions[scope] {
			sort.Slice(b.definitions[scope][name], func(i, j int) bool {
				return jsPositionBefore(b.definitions[scope][name][i].Pos, b.definitions[scope][name][j].Pos)
			})
		}
	}
	for _, item := range b.document.Returns {
		if item.SlotID != "" {
			b.returns[item.ScopeID] = append(b.returns[item.ScopeID], item.SlotID)
		}
	}
	for _, item := range b.resolution.Calls {
		b.calls[item.CallID] = item
	}
}

func (b *jsValueBuilder) addSyntaxFlows() {
	for _, flow := range b.document.Flows {
		b.addFlow(flow.FromID, flow.ToID)
	}
}

// bindReferences connects a use-site reference to definitions in the nearest lexical scope. We keep
// every prior definition in that scope because control-flow facts are deliberately conservative; a
// parser that can prove a narrower def-use relation should emit the precise ValueFlow itself.
func (b *jsValueBuilder) bindReferences() {
	for _, value := range b.document.Values {
		if value.Kind != jsprogram.ValueReference || value.Ref.Kind != jsprogram.ReferenceName || len(value.Ref.Segments) != 1 {
			continue
		}
		name := value.Ref.Segments[0]
		for _, scope := range b.scopeChain(value.ScopeID) {
			definitions := b.definitions[scope][name]
			var prior []jsprogram.Value
			for _, definition := range definitions {
				if definition.Kind == jsprogram.ValueParameter || jsPositionBefore(definition.Pos, value.Pos) {
					prior = append(prior, definition)
				}
			}
			if len(prior) > 0 {
				for _, definition := range prior {
					b.addFlow(definition.ID, value.ID)
				}
				break
			}
		}
	}
}

func (b *jsValueBuilder) modelCalls() {
	for _, call := range b.document.Calls {
		resolved := b.calls[call.ID]
		local := false
		for _, calleeID := range resolved.LocalCallees {
			symbol, ok := b.symbols[calleeID]
			if !ok {
				continue
			}
			switch symbol.Kind {
			case jsprogram.SymbolFunction, jsprogram.SymbolMethod, jsprogram.SymbolArrow:
				local = true
				b.bindCall(call, symbol)
			case jsprogram.SymbolClass:
				if call.Constructor {
					for _, ctor := range b.children[symbol.ID]["constructor"] {
						local = true
						b.bindCall(call, b.symbols[ctor])
					}
				}
			}
		}

		raw := strings.Join(call.Callee.Segments, ".")
		candidates := resolved.ExternalCallees
		matchedRole := false
		for _, model := range b.catalog.Sources {
			if callMatchesJS(model.Pattern, candidates, raw) && call.ResultID != "" {
				matchedRole = true
				for _, class := range model.Classes {
					b.addSource(call.ResultID, class, call.Pos)
				}
			}
		}
		for index, model := range b.catalog.Sinks {
			if !callMatchesJS(model.Pattern, candidates, raw) {
				continue
			}
			matchedRole = true
			if len(b.sinks) >= maxJSTaintSinks {
				b.truncated = true
				continue
			}
			sinkID := "js-sink:" + call.ID + ":" + string(model.Class) + ":" + strconv.Itoa(index)
			b.positions[sinkID] = call.Pos
			b.sinks[sinkID] = JSTypedSink{
				ValueID: sinkID, CallID: call.ID, Callee: trustedJSCallee(candidates, raw),
				Class: model.Class, CWE: model.CWE, Rule: model.Rule, Pos: call.Pos,
			}
			for _, argumentIndex := range model.ArgumentIndexes {
				if argumentIndex >= 0 && argumentIndex < len(call.Arguments) {
					b.addFlow(call.Arguments[argumentIndex].ValueID, sinkID)
				}
			}
			if model.Receiver {
				b.addFlow(call.ReceiverValueID, sinkID)
			}
		}
		for _, model := range b.catalog.Sanitizers {
			if !callMatchesJS(model.Pattern, candidates, raw) || call.ResultID == "" {
				continue
			}
			matchedRole = true
			b.propagateCallInputs(call)
			for _, class := range model.Classes {
				key := call.ResultID + "\x00" + string(class)
				b.sanitizers[key] = JSTypedSanitizer{ValueID: call.ResultID, Class: class}
			}
		}
		// Local functions have explicit parameter/return flow. Unknown/external transforms are opaque,
		// so preserve taint through their result unless a reviewed model already describes the call.
		if !local && !matchedRole {
			b.propagateCallInputs(call)
		}
	}
}

func (b *jsValueBuilder) bindCall(call jsprogram.Call, callee jsprogram.Symbol) {
	parameters := callee.Parameters
	position := 0
	for _, argument := range call.Arguments {
		if argument.ValueID == "" {
			continue
		}
		if argument.Spread {
			for i := position; i < len(parameters); i++ {
				b.addFlow(argument.ValueID, parameters[i].ValueID)
			}
			continue
		}
		if position >= len(parameters) {
			break
		}
		b.addFlow(argument.ValueID, parameters[position].ValueID)
		if !parameters[position].Rest {
			position++
		}
	}
	for _, returnID := range b.returns[callee.ID] {
		b.addFlow(returnID, call.ResultID)
	}
}

func (b *jsValueBuilder) propagateCallInputs(call jsprogram.Call) {
	for _, argument := range call.Arguments {
		b.addFlow(argument.ValueID, call.ResultID)
	}
	b.addFlow(call.ReceiverValueID, call.ResultID)
}

func (b *jsValueBuilder) modelReferenceSources() {
	classes := allClassesForJS(b.catalog)
	for _, value := range b.document.Values {
		if value.Kind != jsprogram.ValueReference || len(value.Ref.Segments) == 0 {
			continue
		}
		raw := strings.Join(value.Ref.Segments, ".")
		for _, suffix := range b.catalog.ReferenceSources {
			if suffixMatch(raw, suffix) {
				for _, class := range classes {
					b.addSource(value.ID, class, value.Pos)
				}
				break
			}
		}
	}
}

func (b *jsValueBuilder) addFlow(from, to string) {
	if from == "" || to == "" || from == to || b.truncated {
		return
	}
	if b.edgeSets[from] == nil {
		b.edgeSets[from] = map[string]bool{}
	}
	if b.edgeSets[from][to] {
		return
	}
	if b.edgeCount >= maxJSValueEdges {
		b.truncated = true
		return
	}
	b.edgeSets[from][to] = true
	b.edgeCount++
}

func (b *jsValueBuilder) addSource(valueID string, class TaintClass, pos jsprogram.Position) {
	if valueID == "" || !class.Valid() {
		return
	}
	if len(b.sources) >= maxJSTaintSources {
		b.truncated = true
		return
	}
	key := valueID + "\x00" + string(class)
	b.sources[key] = JSTypedSource{ValueID: valueID, Class: class, Pos: pos}
}

func (b *jsValueBuilder) scopeChain(scope string) []string {
	var out []string
	seen := map[string]bool{}
	for scope != "" && !seen[scope] {
		seen[scope] = true
		out = append(out, scope)
		scope = b.parents[scope]
	}
	return out
}

func (b *jsValueBuilder) finish() JSValueFlowGraph {
	graph := JSValueFlowGraph{Edges: make(map[string][]string, len(b.edgeSets)), Positions: b.positions, Truncated: b.truncated}
	for from, targets := range b.edgeSets {
		for target := range targets {
			graph.Edges[from] = append(graph.Edges[from], target)
		}
		sort.Strings(graph.Edges[from])
	}
	for _, source := range b.sources { graph.Sources = append(graph.Sources, source) }
	for _, sink := range b.sinks { graph.Sinks = append(graph.Sinks, sink) }
	for _, sanitizer := range b.sanitizers { graph.Sanitizers = append(graph.Sanitizers, sanitizer) }
	sort.Slice(graph.Sources, func(i, j int) bool {
		return graph.Sources[i].ValueID+"\x00"+string(graph.Sources[i].Class) < graph.Sources[j].ValueID+"\x00"+string(graph.Sources[j].Class)
	})
	sort.Slice(graph.Sinks, func(i, j int) bool { return graph.Sinks[i].ValueID < graph.Sinks[j].ValueID })
	sort.Slice(graph.Sanitizers, func(i, j int) bool {
		return graph.Sanitizers[i].ValueID+"\x00"+string(graph.Sanitizers[i].Class) < graph.Sanitizers[j].ValueID+"\x00"+string(graph.Sanitizers[j].Class)
	})
	return graph
}

// Vulnerabilities returns deterministic, bounded, class-specific positive witnesses.
func (g *JSValueFlowGraph) Vulnerabilities() []JSTaintPath {
	sanitized := make(map[string]bool, len(g.Sanitizers))
	for _, item := range g.Sanitizers {
		sanitized[item.ValueID+"\x00"+string(item.Class)] = true
	}
	sinksByID := make(map[string][]JSTypedSink, len(g.Sinks))
	for _, sink := range g.Sinks { sinksByID[sink.ValueID] = append(sinksByID[sink.ValueID], sink) }
	var findings []JSTaintPath
	seenFinding := map[string]bool{}
	work := 0
	for _, source := range g.Sources {
		queue := []string{source.ValueID}
		seen := map[string]bool{source.ValueID: true}
		parent := map[string]string{}
		depth := map[string]int{source.ValueID: 1}
		for len(queue) > 0 {
			work++
			if work > maxJSTaintWork {
				g.Truncated = true
				return sortedJSTaintPaths(findings)
			}
			current := queue[0]
			queue = queue[1:]
			for _, sink := range sinksByID[current] {
				if sink.Class != source.Class { continue }
				key := source.ValueID+"\x00"+sink.ValueID+"\x00"+string(sink.Class)+"\x00"+sink.Rule
				if seenFinding[key] { continue }
				seenFinding[key] = true
				findings = append(findings, JSTaintPath{
					Class: source.Class, CWE: sink.CWE, Rule: sink.Rule, SourceID: source.ValueID,
					SinkID: sink.ValueID, CallID: sink.CallID, Callee: sink.Callee,
					Path: rebuildJSPath(parent, current), SourcePos: source.Pos, SinkPos: sink.Pos,
				})
			}
			if sanitized[current+"\x00"+string(source.Class)] || depth[current] >= maxJSTaintPath {
				continue
			}
			for _, next := range g.Edges[current] {
				if seen[next] { continue }
				seen[next] = true
				parent[next] = current
				depth[next] = depth[current] + 1
				queue = append(queue, next)
			}
		}
	}
	return sortedJSTaintPaths(findings)
}

func validateJSResolution(document jsprogram.Document, resolution jsprogram.Resolution) error {
	calls := make(map[string]bool, len(document.Calls))
	for _, call := range document.Calls { calls[call.ID] = true }
	symbols := make(map[string]bool, len(document.Symbols))
	for _, symbol := range document.Symbols { symbols[symbol.ID] = true }
	seen := map[string]bool{}
	for _, call := range resolution.Calls {
		if !calls[call.CallID] || seen[call.CallID] {
			return fmt.Errorf("%w: invalid javascript call resolution", shared.ErrValidation)
		}
		seen[call.CallID] = true
		for _, id := range call.LocalCallees {
			if !symbols[id] { return fmt.Errorf("%w: javascript resolution references unknown symbol", shared.ErrValidation) }
		}
		for _, external := range call.ExternalCallees {
			if external == "" || len(external) > 4096 || strings.ContainsRune(external, '\x00') {
				return fmt.Errorf("%w: invalid javascript external callee", shared.ErrValidation)
			}
		}
	}
	if len(resolution.Calls) != len(document.Calls) {
		return fmt.Errorf("%w: javascript resolution does not cover every call", shared.ErrValidation)
	}
	return nil
}

func validateJSCatalog(catalog JSCatalog) error {
	if len(catalog.Sources) == 0 || len(catalog.Sinks) == 0 {
		return fmt.Errorf("%w: javascript taint catalog needs sources and sinks", shared.ErrValidation)
	}
	for _, model := range catalog.Sources {
		if !validJSCallablePattern(model.Pattern) || len(model.Classes) == 0 {
			return fmt.Errorf("%w: invalid javascript source model", shared.ErrValidation)
		}
		for _, class := range model.Classes {
			if !class.Valid() { return fmt.Errorf("%w: invalid javascript source taint class", shared.ErrValidation) }
		}
	}
	for _, model := range catalog.Sinks {
		if !validJSCallablePattern(model.Pattern) || !model.Class.Valid() || model.CWE == "" || model.Rule == "" || (len(model.ArgumentIndexes) == 0 && !model.Receiver) {
			return fmt.Errorf("%w: invalid javascript sink model", shared.ErrValidation)
		}
		for _, index := range model.ArgumentIndexes {
			if index < 0 { return fmt.Errorf("%w: invalid javascript sink argument", shared.ErrValidation) }
		}
	}
	for _, model := range catalog.Sanitizers {
		if !validJSCallablePattern(model.Pattern) || len(model.Classes) == 0 {
			return fmt.Errorf("%w: invalid javascript sanitizer model", shared.ErrValidation)
		}
		for _, class := range model.Classes {
			if !class.Valid() { return fmt.Errorf("%w: invalid javascript sanitizer class", shared.ErrValidation) }
		}
	}
	return nil
}

func validJSCallablePattern(pattern JSCallablePattern) bool {
	if len(pattern.RawSuffixes) > 0 { return true }
	return len(pattern.Modules) > 0 && len(pattern.Names) > 0
}

func callMatchesJS(pattern JSCallablePattern, candidates []string, raw string) bool {
	for _, candidate := range candidates {
		for _, module := range pattern.Modules {
			if candidate == module && containsJSName(pattern.Names, "") { return true }
			prefix := module + "."
			if !strings.HasPrefix(candidate, prefix) { continue }
			name := strings.TrimPrefix(candidate, prefix)
			if containsJSName(pattern.Names, name) { return true }
		}
	}
	for _, suffix := range pattern.RawSuffixes {
		if suffixMatch(raw, suffix) { return true }
	}
	return false
}

func containsJSName(items []string, value string) bool {
	for _, item := range items { if item == value { return true } }
	return false
}

func suffixMatch(value, suffix string) bool {
	return value == suffix || strings.HasSuffix(value, "."+suffix)
}

func trustedJSCallee(candidates []string, raw string) string {
	if len(candidates) == 1 { return candidates[0] }
	if raw != "" && len(raw) <= 512 { return raw }
	return "javascript-call"
}

func rebuildJSPath(parent map[string]string, end string) []string {
	path := []string{end}
	for len(path) < maxJSTaintPath {
		previous := parent[path[len(path)-1]]
		if previous == "" { break }
		path = append(path, previous)
	}
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 { path[i], path[j] = path[j], path[i] }
	return path
}

func sortedJSTaintPaths(items []JSTaintPath) []JSTaintPath {
	sort.Slice(items, func(i, j int) bool {
		left := items[i].CallID+"\x00"+string(items[i].Class)+"\x00"+items[i].Rule+"\x00"+items[i].SourceID
		right := items[j].CallID+"\x00"+string(items[j].Class)+"\x00"+items[j].Rule+"\x00"+items[j].SourceID
		return left < right
	})
	return items
}

func allClassesForJS(catalog JSCatalog) []TaintClass {
	seen := map[TaintClass]bool{}
	var out []TaintClass
	for _, source := range catalog.Sources {
		for _, class := range source.Classes {
			if !seen[class] { seen[class] = true; out = append(out, class) }
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func jsPositionBefore(left, right jsprogram.Position) bool {
	if left.File != right.File { return left.File < right.File }
	if left.Line != right.Line { return left.Line < right.Line }
	return left.Column < right.Column
}
