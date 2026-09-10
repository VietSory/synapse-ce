//go:build cgo

package astwalk

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
)

func TestJSFactsDriveRemainingJavaScriptTaintClasses(t *testing.T) {
	root := t.TempDir()
	writeJSFactFile(t, root, "classes.js", `import fs from "fs";
import axios from "axios";
import mongoose from "mongoose";
import _ from "lodash";
export function handler(req, res) {
  mongoose.find(req.body);
  fs.readFile(req.query);
  axios.get(req.query);
  res.send(req.query);
  _.merge({}, req.body);
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
	catalog := taint.DefaultJSCatalog()
	graph, err := taint.BuildJSValueGraph(document, resolution, catalog)
	if err != nil {
		t.Fatalf("BuildJSValueGraph: %v", err)
	}
	paths := graph.Vulnerabilities()
	paths = append(paths, taint.JSPrototypePollutionPaths(document, resolution, catalog, graph)...)
	found := map[string]bool{}
	for _, finding := range paths {
		found[finding.Rule] = true
	}
	for _, want := range []string{
		"javascript-taint-nosql",
		"javascript-taint-path",
		"javascript-taint-ssrf",
		"javascript-taint-xss",
		"js-proto-pollution-bracket",
	} {
		if !found[want] {
			t.Fatalf("missing %s from extracted JavaScript flow; findings=%+v resolution=%+v", want, paths, resolution.Calls)
		}
	}
}
