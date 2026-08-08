package jsresolve

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestMaintainerAuditUnrelatedMalformedSBOMKeepsPositiveButMakesCoverageIncomplete(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"},
		{Name: "@scope/bad", Version: "1.0.0", PURL: "pkg:npm/@scope/bad@1.0.0"},
	}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), doc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusComponent || got.Imports[0].Package.PURL != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("malformed unrelated SBOM component destroyed a valid positive: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if got.Complete {
		t.Fatalf("malformed observed SBOM metadata was silently ignored: %#v", got)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedMetadata) {
		t.Fatalf("malformed SBOM component lacks explicit coverage: %#v", got.Coverage)
	}
}

func TestMaintainerAuditSameNameWorkspaceAmbiguityPreservesBothCandidateClasses(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":       "root",
		"workspaces": []string{"packages/*"},
	})
	writeJSON(t, r2bJoin(root, "packages/shared/package.json"), map[string]any{"name": "shared", "version": "1.0.0"})
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "shared", Version: "2.0.0", PURL: "pkg:npm/shared@2.0.0"}}}

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "shared"), doc)
	if err != nil {
		t.Fatal(err)
	}
	resolution := got.Imports[0]
	if resolution.Status != jsresolution.StatusAmbiguous || got.Complete {
		t.Fatalf("same-name workspace/component collision lost ambiguity: import=%#v coverage=%#v", resolution, got.Coverage)
	}
	workspaceFound := false
	componentFound := false
	for _, candidate := range resolution.Candidates {
		if candidate.Workspace && candidate.Name == "shared" && candidate.Path == "packages/shared" {
			workspaceFound = true
		}
		if !candidate.Workspace && candidate.Name == "shared" && candidate.Version == "2.0.0" && candidate.PURL == "pkg:npm/shared@2.0.0" {
			componentFound = true
		}
	}
	if !workspaceFound || !componentFound || len(resolution.Candidates) != 2 {
		t.Fatalf("ambiguity candidates were not preserved exactly: %#v", resolution.Candidates)
	}
}
