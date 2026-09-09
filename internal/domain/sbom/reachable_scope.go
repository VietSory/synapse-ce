package sbom

import "sort"

// ReachableScopes computes the effective dependency scope for every emitted component that is reachable
// from a dependency-graph root. Component scope seeds root nodes; Dependency.Scope refines each relationship.
// A non-shipping path (development/test/example/fixture/benchmark/docs/vendored) stays non-shipping for all
// descendants, while a component reached by at least one production path is production even if another path
// reaches it through development/test edges.
//
// The graph shapes Synapse accepts are both supported: native parsers omit a synthetic project root, while
// imported CycloneDX documents may include one. An edge whose Ref is not an emitted component is therefore
// treated as a synthetic-root edge and seeds its target from the edge scope (when present) or the target's
// component scope. Components trapped in a rootless cycle are omitted; callers should retain their existing
// component scope as the conservative fallback.
func ReachableScopes(components []Component, deps []Dependency) map[string]string {
	componentScope := make(map[string]string, len(components))
	componentIDs := make(map[string]bool, len(components))
	for _, component := range components {
		id := ComponentID(component.Name, component.Version, component.PURL)
		if id == "" {
			continue
		}
		componentIDs[id] = true
		componentScope[id] = normalizedScope(component.Scope)
	}

	type edge struct {
		to    string
		scope string
	}
	children := make(map[string][]edge)
	componentParents := make(map[string]int, len(componentIDs))
	var syntheticSeeds []edge
	syntheticTargets := make(map[string]bool, len(componentIDs))
	for _, dependency := range deps {
		for _, target := range dependency.DependsOn {
			if !componentIDs[target] || target == dependency.Ref {
				continue
			}
			e := edge{to: target, scope: normalizedScope(dependency.Scope)}
			if componentIDs[dependency.Ref] {
				children[dependency.Ref] = append(children[dependency.Ref], e)
				componentParents[target]++
			} else {
				syntheticSeeds = append(syntheticSeeds, e)
				syntheticTargets[target] = true
			}
		}
	}
	for ref := range children {
		sort.Slice(children[ref], func(i, j int) bool {
			if children[ref][i].to != children[ref][j].to {
				return children[ref][i].to < children[ref][j].to
			}
			return children[ref][i].scope < children[ref][j].scope
		})
	}
	sort.Slice(syntheticSeeds, func(i, j int) bool {
		if syntheticSeeds[i].to != syntheticSeeds[j].to {
			return syntheticSeeds[i].to < syntheticSeeds[j].to
		}
		return syntheticSeeds[i].scope < syntheticSeeds[j].scope
	})

	out := make(map[string]string, len(componentIDs))
	queue := make([]string, 0, len(componentIDs))
	push := func(id, scope string) {
		if !componentIDs[id] {
			return
		}
		scope = normalizedScope(scope)
		merged := mergeReachableScope(out[id], scope)
		if old, exists := out[id]; exists && old == merged {
			return
		}
		out[id] = merged
		queue = append(queue, id)
	}

	roots := make([]string, 0, len(componentIDs))
	for id := range componentIDs {
		if componentParents[id] == 0 && !syntheticTargets[id] {
			roots = append(roots, id)
		}
	}
	sort.Strings(roots)
	for _, root := range roots {
		push(root, componentScope[root])
	}
	for _, seed := range syntheticSeeds {
		scope := seed.scope
		if scope == "" || scope == ScopeUnknown {
			scope = componentScope[seed.to]
		}
		push(seed.to, scope)
	}

	for len(queue) > 0 {
		ref := queue[0]
		queue = queue[1:]
		parentScope := out[ref]
		for _, e := range children[ref] {
			push(e.to, dependencyPathScope(parentScope, e.scope))
		}
	}
	return out
}

// dependencyPathScope combines the scope already accumulated along a path with the next edge. Once a path
// is non-shipping it stays non-shipping; a normal production/unknown edge cannot turn a dev/test path back
// into production. An explicit non-shipping edge can, however, demote a production path from that point on.
func dependencyPathScope(parent, edge string) string {
	parent = normalizedScope(parent)
	edge = normalizedScope(edge)
	if isNonShippingScope(parent) {
		return parent
	}
	if isNonShippingScope(edge) {
		return edge
	}
	if parent == ScopeProduction || edge == ScopeProduction {
		return ScopeProduction
	}
	if parent != "" && parent != ScopeUnknown {
		return parent
	}
	if edge != "" {
		return edge
	}
	return ScopeUnknown
}

// mergeReachableScope combines alternate paths to the same component. Production wins because one
// production path is enough to make the component shipping. Development wins over narrower background
// scopes when every path is non-production; otherwise choose deterministically.
func mergeReachableScope(current, candidate string) string {
	current = normalizedScope(current)
	candidate = normalizedScope(candidate)
	if current == "" || current == ScopeUnknown {
		return candidate
	}
	if candidate == "" || candidate == ScopeUnknown {
		return current
	}
	if current == ScopeProduction || candidate == ScopeProduction {
		return ScopeProduction
	}
	if current == ScopeDevelopment || candidate == ScopeDevelopment {
		return ScopeDevelopment
	}
	if candidate < current {
		return candidate
	}
	return current
}

func isNonShippingScope(scope string) bool {
	return scope == ScopeDevelopment || IsBackgroundScope(scope)
}

func normalizedScope(scope string) string {
	if scope == "" {
		return ScopeUnknown
	}
	return scope
}
