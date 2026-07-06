package sbom

import "testing"

func TestPathToRoot(t *testing.T) {
	deps := []Dependency{
		{Ref: "app", DependsOn: []string{"a"}},
		{Ref: "a", DependsOn: []string{"b"}},
		{Ref: "b", DependsOn: []string{"c"}},
	}
	if got := PathToRoot(deps, "c"); len(got) != 4 || got[0] != "app" || got[3] != "c" {
		t.Errorf("transitive: PathToRoot(c) = %v, want [app a b c]", got)
	}
	if got := PathToRoot(deps, "a"); len(got) != 2 || got[0] != "app" || got[1] != "a" {
		t.Errorf("direct: PathToRoot(a) = %v, want [app a]", got)
	}
	if got := PathToRoot(deps, "app"); len(got) != 1 || got[0] != "app" {
		t.Errorf("root: PathToRoot(app) = %v, want [app]", got)
	}
	if got := PathToRoot(deps, "zzz"); got != nil {
		t.Errorf("absent: PathToRoot(zzz) = %v, want nil", got)
	}
}

func TestPathToRootCycleTerminates(t *testing.T) {
	deps := []Dependency{{Ref: "x", DependsOn: []string{"y"}}, {Ref: "y", DependsOn: []string{"x"}}}
	if got := PathToRoot(deps, "x"); len(got) == 0 {
		t.Error("a cycle with no root must still return a path, not empty/hang")
	}
}

func TestComponentID(t *testing.T) {
	if ComponentID("a", "1", "pkg:npm/a@1") != "pkg:npm/a@1" {
		t.Error("PURL should win")
	}
	if ComponentID("a", "1", "") != "a@1" {
		t.Error("name@version fallback")
	}
	if ComponentID("a", "", "") != "a" {
		t.Error("name-only fallback")
	}
}
