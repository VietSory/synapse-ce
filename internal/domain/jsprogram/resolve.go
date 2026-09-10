package jsprogram

import (
	"path"
	"sort"
	"strings"
)

const maxResolvedCandidates = 128

// CallResolutionStatus records whether a syntactic call has a usable semantic target.
// Partial resolution can still support positive taint evidence, but unresolved/ambiguous
// calls make the overall result incomplete for any future negative proof.
type CallResolutionStatus string

const (
	CallResolved   CallResolutionStatus = "resolved"
	CallExternal   CallResolutionStatus = "external"
	CallAmbiguous  CallResolutionStatus = "ambiguous"
	CallUnresolved CallResolutionStatus = "unresolved"
)

// ResolvedCall separates first-party symbol targets from canonical external callable names.
// ExternalCallees use the stable form module.member (for example child_process.exec), never
// a source-code string. LocalCallees contain Symbol IDs from the validated document.
type ResolvedCall struct {
	CallID          string               `json:"call_id"`
	CallerID        string               `json:"caller_id"`
	LocalCallees    []string             `json:"local_callees,omitempty"`
	ExternalCallees []string             `json:"external_callees,omitempty"`
	Status          CallResolutionStatus `json:"status"`
	Pos             Position             `json:"position"`
	Ambiguous       bool                 `json:"ambiguous,omitempty"`
}

// Resolution is the pure semantic resolution result for one facts snapshot.
type Resolution struct {
	Calls    []ResolvedCall `json:"calls"`
	Gaps     []CoverageGap  `json:"coverage_gaps"`
	Complete bool           `json:"complete"`
}

type jsImportBinding struct {
	module  string
	name    string
	alias   string
	defaultImport bool
	star    bool
}

type semanticResolver struct {
	document       Document
	symbols        map[string]Symbol
	moduleRoots    map[string]string
	moduleFiles    map[string]string
	moduleByFile   map[string]string
	children       map[string]map[string][]string
	imports        map[string]map[string][]jsImportBinding
	parents        map[string]string
	gaps           []CoverageGap
}

// Resolve deterministically resolves first-party function calls and statically-bound ESM/CommonJS
// imports. It does not execute Node resolution or inspect node_modules. Relative imports are matched
// only against files already present in the facts snapshot; package imports remain canonical external
// names for the taint catalog.
func Resolve(document Document) (Resolution, error) {
	if err := document.Validate(); err != nil {
		return Resolution{}, err
	}
	r := newSemanticResolver(document)
	r.indexImports()

	resolved := make([]ResolvedCall, 0, len(document.Calls))
	for _, call := range document.Calls {
		local, external := r.resolveReference(call.CallerID, call.Callee)
		local = sortedUniqueStrings(local)
		external = sortedUniqueStrings(external)
		status := CallResolved
		ambiguous := false
		total := len(local) + len(external)
		switch {
		case total == 0:
			status = CallUnresolved
			r.addGap(GapUnresolvedCall, call.CallerID, "unresolved_call", call.Pos)
		case total > maxResolvedCandidates:
			status = CallAmbiguous
			ambiguous = true
			r.addGap(GapBudget, call.CallerID, "call_candidate_budget", call.Pos)
			local, external = capCandidates(local, external, maxResolvedCandidates)
		case total > 1:
			status = CallAmbiguous
			ambiguous = true
			r.addGap(GapUnresolvedCall, call.CallerID, "ambiguous_call", call.Pos)
		case len(external) == 1:
			status = CallExternal
		}
		resolved = append(resolved, ResolvedCall{
			CallID: call.ID, CallerID: call.CallerID, LocalCallees: local,
			ExternalCallees: external, Status: status, Pos: call.Pos, Ambiguous: ambiguous,
		})
	}
	sort.Slice(resolved, func(i, j int) bool { return resolved[i].CallID < resolved[j].CallID })
	gaps := canonicalJSGaps(append(append([]CoverageGap(nil), document.CoverageGaps...), r.gaps...))
	return Resolution{Calls: resolved, Gaps: gaps, Complete: document.Complete() && len(gaps) == 0}, nil
}

func newSemanticResolver(document Document) *semanticResolver {
	r := &semanticResolver{
		document: document,
		symbols: make(map[string]Symbol, len(document.Symbols)),
		moduleRoots: make(map[string]string, len(document.Modules)),
		moduleFiles: make(map[string]string, len(document.Modules)),
		moduleByFile: make(map[string]string, len(document.Modules)*2),
		children: map[string]map[string][]string{}, imports: map[string]map[string][]jsImportBinding{},
		parents: make(map[string]string, len(document.Symbols)),
	}
	for _, module := range document.Modules {
		r.moduleFiles[module.Name] = module.File
		r.indexModuleFile(module.Name, module.File)
	}
	for _, symbol := range document.Symbols {
		r.symbols[symbol.ID] = symbol
		r.parents[symbol.ID] = symbol.ParentID
		if symbol.Kind == SymbolModule {
			r.moduleRoots[symbol.Module] = symbol.ID
		}
		if symbol.ParentID != "" {
			if r.children[symbol.ParentID] == nil {
				r.children[symbol.ParentID] = map[string][]string{}
			}
			r.children[symbol.ParentID][symbol.Name] = append(r.children[symbol.ParentID][symbol.Name], symbol.ID)
		}
	}
	for parent := range r.children {
		for name := range r.children[parent] {
			sort.Strings(r.children[parent][name])
		}
	}
	return r
}

func (r *semanticResolver) indexModuleFile(module, file string) {
	clean := strings.TrimPrefix(strings.ReplaceAll(file, "\\", "/"), "./")
	base := trimJSExt(clean)
	r.moduleByFile[base] = module
	if strings.HasSuffix(base, "/index") {
		r.moduleByFile[strings.TrimSuffix(base, "/index")] = module
	}
}

func (r *semanticResolver) indexImports() {
	for _, item := range r.document.Imports {
		bound := item.Alias
		if bound == "" {
			switch {
			case item.Name != "":
				bound = item.Name
			case item.Star:
				continue
			default:
				bound = packageRoot(item.Module)
			}
		}
		if bound == "" {
			continue
		}
		if r.imports[item.ScopeID] == nil {
			r.imports[item.ScopeID] = map[string][]jsImportBinding{}
		}
		r.imports[item.ScopeID][bound] = append(r.imports[item.ScopeID][bound], jsImportBinding{
			module: item.Module, name: item.Name, alias: item.Alias, defaultImport: item.Default, star: item.Star,
		})
	}
}

func (r *semanticResolver) resolveReference(scopeID string, ref Reference) ([]string, []string) {
	if len(ref.Segments) == 0 || ref.Kind == ReferenceUnknown || ref.Kind == ReferenceLiteral {
		return nil, nil
	}
	segments := ref.Segments
	if locals := r.lookupLexical(scopeID, segments[0]); len(locals) > 0 {
		var out []string
		for _, id := range locals {
			out = append(out, r.targetsFromLocal(id, segments[1:])...)
		}
		return sortedUniqueStrings(out), nil
	}
	if bindings := r.lookupImports(scopeID, segments[0]); len(bindings) > 0 {
		var local, external []string
		for _, binding := range bindings {
			l, e := r.targetsFromImport(scopeID, binding, segments)
			local = append(local, l...)
			external = append(external, e...)
		}
		return sortedUniqueStrings(local), sortedUniqueStrings(external)
	}
	if len(segments) == 1 && (segments[0] == "eval" || segments[0] == "fetch" || segments[0] == "encodeURIComponent" || segments[0] == "decodeURIComponent") {
		return nil, []string{"global." + segments[0]}
	}
	return nil, nil
}

func (r *semanticResolver) lookupLexical(scopeID, name string) []string {
	for _, scope := range r.scopeChain(scopeID) {
		if ids := r.children[scope][name]; len(ids) > 0 {
			return ids
		}
	}
	return nil
}

func (r *semanticResolver) lookupImports(scopeID, name string) []jsImportBinding {
	for _, scope := range r.scopeChain(scopeID) {
		if bindings := r.imports[scope][name]; len(bindings) > 0 {
			return bindings
		}
	}
	return nil
}

func (r *semanticResolver) scopeChain(scope string) []string {
	var out []string
	seen := map[string]bool{}
	for scope != "" && !seen[scope] {
		seen[scope] = true
		out = append(out, scope)
		scope = r.parents[scope]
	}
	return out
}

func (r *semanticResolver) targetsFromLocal(id string, rest []string) []string {
	symbol, ok := r.symbols[id]
	if !ok {
		return nil
	}
	if len(rest) == 0 {
		switch symbol.Kind {
		case SymbolFunction, SymbolMethod, SymbolArrow, SymbolClass:
			return []string{id}
		default:
			return nil
		}
	}
	current := []string{id}
	for _, part := range rest {
		var next []string
		for _, parent := range current {
			next = append(next, r.children[parent][part]...)
		}
		current = sortedUniqueStrings(next)
		if len(current) == 0 {
			return nil
		}
	}
	var out []string
	for _, candidate := range current {
		switch r.symbols[candidate].Kind {
		case SymbolFunction, SymbolMethod, SymbolArrow, SymbolClass:
			out = append(out, candidate)
		}
	}
	return out
}

func (r *semanticResolver) targetsFromImport(scopeID string, binding jsImportBinding, segments []string) ([]string, []string) {
	module, local := r.localModule(scopeID, binding.module)
	var member []string
	switch {
	case binding.star:
		member = append(member, segments[1:]...)
	case binding.defaultImport:
		member = append(member, segments[1:]...)
	case binding.name != "":
		member = append(member, binding.name)
		member = append(member, segments[1:]...)
	default:
		member = append(member, segments[1:]...)
	}
	if local {
		root := r.moduleRoots[module]
		if root == "" || len(member) == 0 {
			return nil, nil
		}
		return r.targetsFromLocal(root, member), nil
	}
	canonical := strings.TrimSpace(binding.module)
	if canonical == "" {
		return nil, nil
	}
	if len(member) > 0 {
		canonical += "." + strings.Join(member, ".")
	}
	return nil, []string{canonical}
}

func (r *semanticResolver) localModule(scopeID, specifier string) (string, bool) {
	if _, ok := r.moduleRoots[specifier]; ok {
		return specifier, true
	}
	if !strings.HasPrefix(specifier, ".") {
		return "", false
	}
	owner := r.enclosingModule(scopeID)
	file := r.moduleFiles[owner]
	if file == "" {
		return "", false
	}
	candidate := path.Clean(path.Join(path.Dir(file), specifier))
	candidate = trimJSExt(candidate)
	if module, ok := r.moduleByFile[candidate]; ok {
		return module, true
	}
	if module, ok := r.moduleByFile[path.Join(candidate, "index")]; ok {
		return module, true
	}
	return "", false
}

func (r *semanticResolver) enclosingModule(scopeID string) string {
	for _, scope := range r.scopeChain(scopeID) {
		if symbol, ok := r.symbols[scope]; ok && symbol.Kind == SymbolModule {
			return symbol.Module
		}
	}
	return ""
}

func (r *semanticResolver) addGap(kind GapKind, symbolID, detail string, pos Position) {
	r.gaps = append(r.gaps, CoverageGap{Kind: kind, SymbolID: symbolID, Detail: detail, Pos: pos})
}

func canonicalJSGaps(items []CoverageGap) []CoverageGap {
	seen := map[string]bool{}
	out := make([]CoverageGap, 0, len(items))
	for _, item := range items {
		key := string(item.Kind) + "\x00" + item.SymbolID + "\x00" + item.Detail + "\x00" + item.Pos.File
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Pos.File != out[j].Pos.File { return out[i].Pos.File < out[j].Pos.File }
		if out[i].Pos.Line != out[j].Pos.Line { return out[i].Pos.Line < out[j].Pos.Line }
		if out[i].Pos.Column != out[j].Pos.Column { return out[i].Pos.Column < out[j].Pos.Column }
		if out[i].Kind != out[j].Kind { return out[i].Kind < out[j].Kind }
		if out[i].SymbolID != out[j].SymbolID { return out[i].SymbolID < out[j].SymbolID }
		return out[i].Detail < out[j].Detail
	})
	return out
}

func capCandidates(local, external []string, limit int) ([]string, []string) {
	if len(local) >= limit {
		return local[:limit], nil
	}
	remaining := limit - len(local)
	if len(external) > remaining {
		external = external[:remaining]
	}
	return local, external
}

func sortedUniqueStrings(items []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if item != "" && !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	sort.Strings(out)
	return out
}

func trimJSExt(file string) string {
	for _, ext := range []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"} {
		if strings.HasSuffix(file, ext) {
			return strings.TrimSuffix(file, ext)
		}
	}
	return file
}

func packageRoot(module string) string {
	module = strings.TrimSpace(module)
	if module == "" || strings.HasPrefix(module, ".") {
		return ""
	}
	parts := strings.Split(module, "/")
	if strings.HasPrefix(module, "@") && len(parts) >= 2 {
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}
