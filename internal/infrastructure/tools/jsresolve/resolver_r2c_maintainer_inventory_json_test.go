package jsresolve

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
)

func TestMaintainerAuditDuplicateWorkspacePackageNameDoesNotCreateWorkspaceIdentity(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":       "root",
		"workspaces": []string{"packages/*"},
	})
	writeFile(t, r2bJoin(root, "packages/shared/package.json"), `{
  "name": "evil",
  "name": "shared",
  "version": "1.0.0"
}`)

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "shared"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusWorkspace {
		t.Fatalf("duplicate package.json name created a workspace identity: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if got.Complete {
		t.Fatalf("duplicate workspace package metadata left resolution complete: %#v", got)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageMalformedMetadata) {
		t.Fatalf("duplicate workspace package metadata lacks malformed coverage: %#v", got.Coverage)
	}
}

func TestMaintainerAuditDuplicateRootWorkspacesDoesNotSelectLastDeclaration(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, r2bJoin(root, "package.json"), `{
  "name": "root",
  "workspaces": ["packages/a"],
  "workspaces": ["packages/b"]
}`)
	writeJSON(t, r2bJoin(root, "packages/a/package.json"), map[string]any{"name": "a", "version": "1.0.0"})
	writeJSON(t, r2bJoin(root, "packages/b/package.json"), map[string]any{"name": "b", "version": "1.0.0"})

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "b"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status == jsresolution.StatusWorkspace {
		t.Fatalf("duplicate workspaces key selected the last declaration: import=%#v coverage=%#v", got.Imports[0], got.Coverage)
	}
	if got.Complete || !hasCoverageKind(got.Coverage, jsresolution.CoverageMalformedMetadata) {
		t.Fatalf("duplicate workspaces metadata was not fail-closed: %#v", got)
	}
}
