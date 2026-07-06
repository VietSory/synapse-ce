package govulncheck

import (
	"reflect"
	"strings"
	"testing"
)

// govulncheckStream is a representative `govulncheck -json -scan=symbol` NDJSON stream (protocol v1.0.0):
// a config message, two symbol-level findings whose traces are ordered VULN-SYMBOL → ENTRYPOINT, a
// module-level finding (no symbol path), and a REPEATED finding (the stream may emit one several times).
const govulncheckStream = `
{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck"}}
{"osv":{"id":"GO-2024-0001"}}
{"finding":{"osv":"GO-2024-0001","trace":[
  {"package":"golang.org/x/text/language","function":"Parse"},
  {"package":"example.com/app/internal/tags","function":"parseTag"},
  {"package":"example.com/app","function":"main"}
]}}
{"finding":{"osv":"GO-2024-0002","trace":[
  {"package":"golang.org/x/crypto/cipher","receiver":"*StreamReader","function":"Read"},
  {"package":"example.com/app","function":"main"}
]}}
{"finding":{"osv":"GO-2024-0003","trace":[
  {"module":"example.com/app"}
]}}
{"finding":{"osv":"GO-2024-0001","trace":[
  {"package":"golang.org/x/text/language","function":"Parse"},
  {"package":"example.com/app/internal/tags","function":"parseTag"},
  {"package":"example.com/app","function":"main"}
]}}
`

func TestParseGovulncheck(t *testing.T) {
	g, err := parseGovulncheck([]byte(govulncheckStream))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// entrypoint = the LAST trace frame (both findings share main, deduped)
	if !reflect.DeepEqual(g.Entrypoints, []string{"example.com/app.main"}) {
		t.Fatalf("entrypoints = %v, want [example.com/app.main]", g.Entrypoints)
	}

	// PROOF path: trace walked tail-to-head -> main -> parseTag -> vulnerable x/text/language.Parse
	wantPath := []string{
		"example.com/app.main",
		"example.com/app/internal/tags.parseTag",
		"golang.org/x/text/language.Parse",
	}
	if got := g.PathTo("golang.org/x/text/language.Parse"); !reflect.DeepEqual(got, wantPath) {
		t.Errorf("PathTo(x/text Parse) = %v, want %v", got, wantPath)
	}

	// method-level node composes the receiver (`*StreamReader` -> StreamReader), matching OSV's
	// importPath.Type.Method affected-symbol form
	const method = "golang.org/x/crypto/cipher.StreamReader.Read"
	if got := g.PathTo(method); !reflect.DeepEqual(got, []string{"example.com/app.main", method}) {
		t.Errorf("PathTo(method) = %v, want [main, %s]", got, method)
	}

	// the module-level finding (no symbol) contributes no node
	if g.Reaches("example.com/app") {
		t.Error("a module-level finding must not produce a reachable symbol")
	}
}

func TestParseGovulncheckDeterministicAndDeduped(t *testing.T) {
	// parsing twice yields an identical canonical Graph (sorted entrypoints + edges + callees), and the
	// repeated GO-2024-0001 finding did not duplicate any edge.
	a, _ := parseGovulncheck([]byte(govulncheckStream))
	b, _ := parseGovulncheck([]byte(govulncheckStream))
	if !reflect.DeepEqual(a, b) {
		t.Fatal("parse must be deterministic for the same input")
	}
	for _, e := range a.Edges {
		seen := map[string]bool{}
		for _, c := range e.Callees {
			if seen[c] {
				t.Errorf("caller %q has a duplicate callee %q (dedup failed)", e.Caller, c)
			}
			seen[c] = true
		}
	}
	// main calls exactly parseTag + the cipher method (sorted); no dupes from the repeated finding
	var mainCallees []string
	for _, e := range a.Edges {
		if e.Caller == "example.com/app.main" {
			mainCallees = e.Callees
		}
	}
	want := []string{"example.com/app/internal/tags.parseTag", "golang.org/x/crypto/cipher.StreamReader.Read"}
	if !reflect.DeepEqual(mainCallees, want) {
		t.Errorf("main callees = %v, want %v", mainCallees, want)
	}
}

func TestParseGovulncheckProtocolMismatch(t *testing.T) {
	// a drifted protocol version fails closed rather than silently mis-parsing.
	const drifted = `{"config":{"protocol_version":"v2.0.0"}}`
	if _, err := parseGovulncheck([]byte(drifted)); err == nil || !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("want a protocol-mismatch error, got %v", err)
	}
}

func TestParseGovulncheckEmpty(t *testing.T) {
	// no findings -> an empty but non-nil Graph (so a caller degrades to a lower tier, not a nil deref).
	g, err := parseGovulncheck([]byte(`{"config":{"protocol_version":"v1.0.0"}}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if g == nil {
		t.Fatal("graph must be non-nil")
	}
	if len(g.Entrypoints) != 0 || len(g.Edges) != 0 {
		t.Errorf("empty stream must yield an empty graph, got %+v", g)
	}
}
