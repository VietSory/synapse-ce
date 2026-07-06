package gomodgraph

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeRunner struct {
	gotSpec ports.ToolSpec
	result  ports.ToolResult
	err     error
}

func (f *fakeRunner) Run(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	f.gotSpec = spec
	return f.result, f.err
}

// go mod graph output: the main module (no @version) + selected deps + an UNSELECTED older version of c
// (MVS lists every version it considered). Only edges between SBOM components must survive.
const modGraph = `app golang.org/x/text@v0.3.8
app github.com/pkg/errors@v0.9.1
golang.org/x/text@v0.3.8 golang.org/x/tools@v0.1.0
golang.org/x/text@v0.3.0 golang.org/x/tools@v0.1.0
`

func docWith(purls ...string) *sbom.SBOM {
	var comps []sbom.Component
	for _, p := range purls {
		comps = append(comps, sbom.Component{PURL: p})
	}
	return &sbom.SBOM{Components: comps}
}

func TestResolveEdges(t *testing.T) {
	doc := docWith(
		"pkg:golang/golang.org/x/text@v0.3.8",
		"pkg:golang/github.com/pkg/errors@v0.9.1",
		"pkg:golang/golang.org/x/tools@v0.1.0",
		"pkg:npm/lodash@4.17.21", // a non-go component must be ignored
	)
	fr := &fakeRunner{result: ports.ToolResult{Stdout: []byte(modGraph)}}
	n, err := New("go").WithRunner(fr).ResolveEdges(context.Background(), "/work/m", doc)
	if err != nil {
		t.Fatalf("ResolveEdges: %v", err)
	}
	// Edges: app→text + app→errors are dropped (app, the main module, is not an SBOM component);
	// text@v0.3.8→tools@v0.1.0 survives; text@v0.3.0→tools is dropped (v0.3.0 not a component, MVS-unselected).
	if n != 1 {
		t.Fatalf("want 1 edge added, got %d (deps: %+v)", n, doc.Dependencies)
	}
	want := []sbom.Dependency{{
		Ref:       "pkg:golang/golang.org/x/text@v0.3.8",
		DependsOn: []string{"pkg:golang/golang.org/x/tools@v0.1.0"},
	}}
	if !reflect.DeepEqual(doc.Dependencies, want) {
		t.Errorf("edges mismatch:\n got %+v\nwant %+v", doc.Dependencies, want)
	}
	// The spec must confine the run: argv `-C <dir> mod graph`, dir read-only, GOPROXY=off (offline).
	s := fr.gotSpec
	if !reflect.DeepEqual(s.Args, []string{"-C", "/work/m", "mod", "graph"}) {
		t.Errorf("args wrong: %+v", s.Args)
	}
	if !reflect.DeepEqual(s.ReadOnlyPaths, []string{"/work/m"}) {
		t.Errorf("module dir must be read-only: %+v", s.ReadOnlyPaths)
	}
	if !contains(s.Env, "GOPROXY=off") {
		t.Errorf("GOPROXY=off must force offline (cache-only): %+v", s.Env)
	}
	if !contains(s.Env, "GOTOOLCHAIN=local") {
		t.Errorf("GOTOOLCHAIN=local must prevent a hostile toolchain directive from fetching: %+v", s.Env)
	}
	if contains(s.Env, "GOFLAGS=-mod=mod") {
		t.Errorf("-mod=mod must NOT be set (it permits writes against the read-only mount): %+v", s.Env)
	}
}

func TestResolveEdgesNoGoComponentsNoOp(t *testing.T) {
	// A non-Go SBOM must NOT run the tool (no go components to resolve against).
	fr := &fakeRunner{err: errors.New("should not be called")}
	n, err := New("").WithRunner(fr).ResolveEdges(context.Background(), "/work/m", docWith("pkg:npm/x@1.0.0"))
	if err != nil || n != 0 {
		t.Fatalf("a non-Go SBOM must no-op cleanly, got n=%d err=%v", n, err)
	}
	if fr.gotSpec.Name != "" {
		t.Error("the tool must NOT be run when there are no go components")
	}
}

func TestResolveEdgesToolErrorBestEffort(t *testing.T) {
	doc := docWith("pkg:golang/x@v1.0.0")
	fr := &fakeRunner{result: ports.ToolResult{ExitCode: 1, Stderr: []byte("no required module provides package")}}
	n, err := New("").WithRunner(fr).ResolveEdges(context.Background(), "/work/m", doc)
	if err == nil {
		t.Error("a non-zero exit must surface an error (the caller logs+ignores it best-effort)")
	}
	if n != 0 || len(doc.Dependencies) != 0 {
		t.Errorf("a failed run must add no edges, got n=%d deps=%+v", n, doc.Dependencies)
	}
}

func TestResolveEdgesNilDoc(t *testing.T) {
	if n, err := New("").ResolveEdges(context.Background(), "/x", nil); n != 0 || err != nil {
		t.Errorf("nil doc must no-op, got n=%d err=%v", n, err)
	}
}

func TestMergeEdgesFoldsExistingRef(t *testing.T) {
	// An edge whose source already has a Dependency (from another parser) must FOLD in, not duplicate the Ref.
	doc := docWith("pkg:golang/a@v1", "pkg:golang/b@v1", "pkg:golang/c@v1")
	doc.Dependencies = []sbom.Dependency{{Ref: "pkg:golang/a@v1", DependsOn: []string{"pkg:golang/b@v1"}}}
	fr := &fakeRunner{result: ports.ToolResult{Stdout: []byte("a@v1 b@v1\na@v1 c@v1\n")}}
	n, err := New("").WithRunner(fr).ResolveEdges(context.Background(), "/m", doc)
	if err != nil {
		t.Fatalf("ResolveEdges: %v", err)
	}
	// a→b already present (not re-added); a→c is new. One Dependency entry for a, two targets.
	if n != 1 || len(doc.Dependencies) != 1 {
		t.Fatalf("want 1 new edge folded into the single a Ref, got n=%d deps=%+v", n, doc.Dependencies)
	}
	if got := doc.Dependencies[0].DependsOn; !reflect.DeepEqual(got, []string{"pkg:golang/b@v1", "pkg:golang/c@v1"}) {
		t.Errorf("a must depend on b+c (deduped, b not re-added), got %v", got)
	}
}

func TestModTokenToPURL(t *testing.T) {
	cases := map[string]string{
		"github.com/pkg/errors@v0.9.1": "pkg:golang/github.com/pkg/errors@v0.9.1",
		"app":                          "", // main module, no @version
		"x@":                           "", // empty version
		"@v1":                          "", // empty path
		"":                             "",
	}
	for in, want := range cases {
		if got := modTokenToPURL(in); got != want {
			t.Errorf("modTokenToPURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
