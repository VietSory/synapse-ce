package taint

import (
	"sort"
	"strconv"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
)

// TaintPrototypePollution is JS-specific because prototype-chain mutation is a JavaScript object-model
// weakness rather than a cross-language neutralization class. It intentionally does not extend the shared
// TaintClass.Valid vocabulary used by Python custom rules; this pass mints only positive CWE-1321 witnesses.
const TaintPrototypePollution TaintClass = "prototype_pollution"

// JSPrototypePollutionPaths finds request-controlled values that reach the source-object argument of a
// reviewed recursive merge helper. It runs over the same bounded value graph as the normal class-specific
// taint pass, so assignments and local argument/parameter/return edges are honored without executing target
// code. There is deliberately no generic raw "merge" fallback: only semantically-resolved package calls in
// JSCatalog.PrototypeMerges can produce a witness.
func JSPrototypePollutionPaths(document jsprogram.Document, resolution jsprogram.Resolution, catalog JSCatalog, graph JSValueFlowGraph) []JSTaintPath {
	if len(catalog.PrototypeMerges) == 0 || len(graph.Sources) == 0 || len(document.Calls) == 0 {
		return nil
	}

	resolved := make(map[string]jsprogram.ResolvedCall, len(resolution.Calls))
	for _, call := range resolution.Calls {
		resolved[call.CallID] = call
	}

	// Every normal request source is stamped once per ordinary taint class. Collapse those copies to one
	// source slot for CWE-1321 while retaining deterministic position selection.
	sourcePos := map[string]jsprogram.Position{}
	for _, source := range graph.Sources {
		if source.ValueID == "" {
			continue
		}
		if current, ok := sourcePos[source.ValueID]; !ok || jsPositionBefore(source.Pos, current) {
			sourcePos[source.ValueID] = source.Pos
		}
	}
	sourceIDs := make([]string, 0, len(sourcePos))
	for id := range sourcePos {
		sourceIDs = append(sourceIDs, id)
	}
	sort.Strings(sourceIDs)

	var findings []JSTaintPath
	seen := map[string]bool{}
	for _, call := range document.Calls {
		resolution := resolved[call.ID]
		raw := joinJSReference(call.Callee)
		for modelIndex, model := range catalog.PrototypeMerges {
			if !validJSCallablePattern(model.Pattern) || !callMatchesJS(model.Pattern, resolution.ExternalCallees, raw) {
				continue
			}
			for _, argumentIndex := range model.ArgumentIndexes {
				if argumentIndex < 0 || argumentIndex >= len(call.Arguments) {
					continue
				}
				target := call.Arguments[argumentIndex].ValueID
				if target == "" {
					continue
				}
				for _, sourceID := range sourceIDs {
					path, ok := jsValuePath(graph.Edges, sourceID, target)
					if !ok {
						continue
					}
					key := call.ID + "\x00" + strconv.Itoa(modelIndex) + "\x00" + strconv.Itoa(argumentIndex) + "\x00" + sourceID
					if seen[key] {
						continue
					}
					seen[key] = true
					findings = append(findings, JSTaintPath{
						Class: TaintPrototypePollution, CWE: "CWE-1321", Rule: "js-proto-pollution-bracket",
						SourceID: sourceID, SinkID: target, CallID: call.ID,
						Callee: trustedJSCallee(resolution.ExternalCallees, raw), Path: path,
						SourcePos: sourcePos[sourceID], SinkPos: call.Pos,
					})
				}
			}
		}
	}
	return sortedJSTaintPaths(findings)
}

func joinJSReference(ref jsprogram.Reference) string {
	if len(ref.Segments) == 0 {
		return ""
	}
	out := ref.Segments[0]
	for _, segment := range ref.Segments[1:] {
		out += "." + segment
	}
	return out
}

// jsValuePath returns one deterministic shortest value-flow path, including both endpoints. The search is
// bounded by the same path/work ceilings as the main JS taint traversal; failure to find a path simply
// yields no positive witness and can never be interpreted as a clean proof.
func jsValuePath(edges map[string][]string, source, target string) ([]string, bool) {
	if source == "" || target == "" {
		return nil, false
	}
	if source == target {
		return []string{source}, true
	}
	queue := []string{source}
	seen := map[string]bool{source: true}
	parent := map[string]string{}
	depth := map[string]int{source: 1}
	work := 0
	for len(queue) > 0 {
		work++
		if work > maxJSTaintWork {
			return nil, false
		}
		current := queue[0]
		queue = queue[1:]
		if depth[current] >= maxJSTaintPath {
			continue
		}
		for _, next := range edges[current] {
			if seen[next] {
				continue
			}
			seen[next] = true
			parent[next] = current
			depth[next] = depth[current] + 1
			if next == target {
				return rebuildJSPath(parent, target), true
			}
			queue = append(queue, next)
		}
	}
	return nil, false
}
