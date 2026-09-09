package sbom

import "testing"

func TestReachableScopes(t *testing.T) {
	component := func(id, scope string) Component {
		return Component{Name: id, PURL: id, Scope: scope}
	}

	tests := []struct {
		name       string
		components []Component
		deps       []Dependency
		want       map[string]string
	}{
		{
			name: "dev-only transitive path stays development",
			components: []Component{
				component("dev-root", ScopeDevelopment),
				component("mid", ScopeProduction),
				component("leaf", ScopeProduction),
			},
			deps: []Dependency{
				{Ref: "dev-root", DependsOn: []string{"mid"}, Scope: ScopeProduction},
				{Ref: "mid", DependsOn: []string{"leaf"}, Scope: ScopeProduction},
			},
			want: map[string]string{
				"dev-root": ScopeDevelopment,
				"mid":      ScopeDevelopment,
				"leaf":     ScopeDevelopment,
			},
		},
		{
			name: "production path wins a dev production diamond",
			components: []Component{
				component("root", ScopeProduction),
				component("prod-branch", ScopeProduction),
				component("dev-branch", ScopeProduction),
				component("leaf", ScopeProduction),
			},
			deps: []Dependency{
				{Ref: "root", DependsOn: []string{"prod-branch"}, Scope: ScopeProduction},
				{Ref: "root", DependsOn: []string{"dev-branch"}, Scope: ScopeDevelopment},
				{Ref: "prod-branch", DependsOn: []string{"leaf"}, Scope: ScopeProduction},
				{Ref: "dev-branch", DependsOn: []string{"leaf"}, Scope: ScopeProduction},
			},
			want: map[string]string{
				"root":        ScopeProduction,
				"prod-branch": ScopeProduction,
				"dev-branch":  ScopeDevelopment,
				"leaf":        ScopeProduction,
			},
		},
		{
			name: "synthetic project root does not erase direct component scope",
			components: []Component{
				component("direct-dev", ScopeDevelopment),
				component("leaf", ScopeProduction),
			},
			deps: []Dependency{
				{Ref: "project-root", DependsOn: []string{"direct-dev"}},
				{Ref: "direct-dev", DependsOn: []string{"leaf"}, Scope: ScopeProduction},
			},
			want: map[string]string{
				"direct-dev": ScopeDevelopment,
				"leaf":       ScopeDevelopment,
			},
		},
		{
			name: "synthetic project root edge scope overrides production-shaped component",
			components: []Component{
				component("direct", ScopeProduction),
				component("leaf", ScopeProduction),
			},
			deps: []Dependency{
				{Ref: "project-root", DependsOn: []string{"direct"}, Scope: ScopeDevelopment},
				{Ref: "direct", DependsOn: []string{"leaf"}, Scope: ScopeProduction},
			},
			want: map[string]string{
				"direct": ScopeDevelopment,
				"leaf":   ScopeDevelopment,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ReachableScopes(tt.components, tt.deps)
			if len(got) != len(tt.want) {
				t.Fatalf("ReachableScopes() returned %d components, want %d: %#v", len(got), len(tt.want), got)
			}
			for id, want := range tt.want {
				if got[id] != want {
					t.Errorf("ReachableScopes()[%q] = %q, want %q", id, got[id], want)
				}
			}
		})
	}
}
