//go:build cgo

package astwalk

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
)

func TestJSFactsForExtractsJavaScriptTypeScriptAndTSXDeterministically(t *testing.T) {
	root := t.TempDir()
	writeJSFactFile(t, root, "app.js", `import { exec as run } from "node:child_process";
import pg from "pg";
function passthrough(value) { return value; }
export function handler(req, res) {
  const query = passthrough(req.query.q);
  pg.query(query);
  return run(query);
}
`)
	writeJSFactFile(t, root, "service.ts", `import axios from "axios";
export const fetchURL = async (url: string): Promise<unknown> => {
  const target: string = url;
  return axios.get(target);
};
`)
	writeJSFactFile(t, root, "view.tsx", `export function View(props: { name: string }) {
  const name = props.name;
  return <div>{name}</div>;
}
`)

	first, err := JSFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JSFactsFor: %v", err)
	}
	second, err := JSFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JSFactsFor second run: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		left, _ := json.Marshal(first)
		right, _ := json.Marshal(second)
		t.Fatalf("facts are not deterministic:\n%s\n%s", left, right)
	}
	if first.FilesSeen != 3 || first.FilesParsed != 3 {
		t.Fatalf("coverage = seen:%d parsed:%d gaps:%+v", first.FilesSeen, first.FilesParsed, first.CoverageGaps)
	}
	for _, want := range []string{"app", "service", "view"} {
		if !hasJSModule(first, want) {
			t.Errorf("missing module %q", want)
		}
	}
	for _, want := range []string{"passthrough", "handler", "fetchURL", "View"} {
		if !hasJSSymbol(first, want) {
			t.Errorf("missing symbol %q (symbols: %+v)", want, first.Symbols)
		}
	}
	for _, want := range []string{"passthrough", "pg.query", "run", "axios.get"} {
		if !hasJSCall(first, want) {
			t.Errorf("missing call %q (calls: %+v)", want, first.Calls)
		}
	}
	if !hasJSImport(first, "node:child_process", "exec", "run") || !hasJSImport(first, "pg", "", "pg") || !hasJSImport(first, "axios", "", "axios") {
		t.Fatalf("imports = %+v", first.Imports)
	}
	if len(first.Values) == 0 || len(first.Flows) == 0 || len(first.Returns) == 0 {
		t.Fatalf("value extraction missing: values=%d flows=%d returns=%d", len(first.Values), len(first.Flows), len(first.Returns))
	}
	for _, call := range first.Calls {
		if call.ResultID == "" {
			t.Errorf("call %q has no result value", call.ID)
		}
		for _, argument := range call.Arguments {
			if argument.ValueID == "" {
				t.Errorf("call %q has argument without value slot", call.ID)
			}
		}
	}
}

func TestJSFactsDriveInterproceduralSemanticTaint(t *testing.T) {
	root := t.TempDir()
	writeJSFactFile(t, root, "app.js", `import { exec as run } from "node:child_process";
import pg from "pg";
function passthrough(value) { return value; }
export function handler(req) {
  const query = passthrough(req.query.q);
  pg.query(query);
  run(query);
}
`)
	document, err := JSFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JSFactsFor: %v", err)
	}
	resolution, err := jsprogram.Resolve(document)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	graph, err := taint.BuildJSValueGraph(document, resolution, taint.DefaultJSCatalog())
	if err != nil {
		t.Fatalf("BuildJSValueGraph: %v", err)
	}
	found := map[string]bool{}
	for _, finding := range graph.Vulnerabilities() {
		found[finding.Rule] = true
	}
	for _, want := range []string{"javascript-taint-sqli", "javascript-taint-command"} {
		if !found[want] {
			t.Fatalf("missing %s from extracted interprocedural flow; findings=%+v resolution=%+v", want, graph.Vulnerabilities(), resolution.Calls)
		}
	}
}

func TestJSFactsForReportsDynamicAndRecoveryGaps(t *testing.T) {
	root := t.TempDir()
	writeJSFactFile(t, root, "dynamic.js", `function load(name, obj, key) {
  const module = import(name);
  return obj[key];
}
`)
	writeJSFactFile(t, root, "broken.ts", `export function broken(: string) { return 1; }
`)

	document, err := JSFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JSFactsFor: %v", err)
	}
	if document.Complete() {
		t.Fatal("dynamic or recovered source must not support a complete negative proof")
	}
	for _, want := range []jsprogram.GapKind{jsprogram.GapDynamicProperty, jsprogram.GapParseRecovery} {
		if !hasJSGap(document, want) {
			t.Errorf("missing coverage gap %q (all: %+v)", want, document.CoverageGaps)
		}
	}
}

func writeJSFactFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func hasJSModule(document jsprogram.Document, name string) bool {
	for _, module := range document.Modules {
		if module.Name == name {
			return true
		}
	}
	return false
}

func hasJSSymbol(document jsprogram.Document, name string) bool {
	for _, symbol := range document.Symbols {
		if symbol.Name == name {
			return true
		}
	}
	return false
}

func hasJSCall(document jsprogram.Document, want string) bool {
	for _, call := range document.Calls {
		if joinJSRef(call.Callee) == want {
			return true
		}
	}
	return false
}

func hasJSImport(document jsprogram.Document, module, name, alias string) bool {
	for _, item := range document.Imports {
		if item.Module == module && item.Name == name && item.Alias == alias {
			return true
		}
	}
	return false
}

func hasJSGap(document jsprogram.Document, kind jsprogram.GapKind) bool {
	for _, gap := range document.CoverageGaps {
		if gap.Kind == kind {
			return true
		}
	}
	return false
}

func joinJSRef(ref jsprogram.Reference) string {
	var out string
	for _, segment := range ref.Segments {
		if out != "" {
			out += "."
		}
		out += segment
	}
	return out
}
