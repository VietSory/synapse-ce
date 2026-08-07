package jsresolve

import (
	"context"
	"path/filepath"
	"testing"
)

// These tests are intentionally audit-only. Each asserts the safety rule that
// supported metadata must be interpreted correctly, while unsupported valid
// metadata must make coverage incomplete rather than silently looking complete.
func TestAuditPNPMRootIsAlwaysWorkspace(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, filepath.Join(root, "package.json"), map[string]any{"name": "root-pkg", "private": true})
	writeFile(t, filepath.Join(root, "pnpm-workspace.yaml"), "packages:\n  - 'packages/*'\n")
	writeJSON(t, filepath.Join(root, "packages", "child", "package.json"), map[string]any{"name": "child"})

	got, err := NewInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Complete {
		t.Fatalf("valid pnpm workspace unexpectedly incomplete: %#v", got.Coverage)
	}
	byPath := packagesByPath(got.Packages)
	if !byPath["."].Workspace {
		t.Fatalf("pnpm root package must be part of the workspace: %#v", byPath["."])
	}
}

func TestAuditPNPMOmittedPackagesMeansRootOnlyWorkspace(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, filepath.Join(root, "package.json"), map[string]any{"name": "root-pkg", "private": true})
	writeFile(t, filepath.Join(root, "pnpm-workspace.yaml"), "catalog:\n  chalk: ^5.0.0\n")

	got, err := NewInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Complete {
		t.Fatalf("pnpm root-only workspace is valid but was marked incomplete: %#v", got.Coverage)
	}
	if !packagesByPath(got.Packages)["."].Workspace {
		t.Fatalf("pnpm root-only workspace did not mark root as workspace: %#v", got.Packages)
	}
}

func TestAuditExtendedGlobCannotSilentlyDisappear(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, filepath.Join(root, "package.json"), map[string]any{
		"name": "root", "private": true, "workspaces": []string{"packages/@(a|b)"},
	})
	writeJSON(t, filepath.Join(root, "packages", "a", "package.json"), map[string]any{"name": "a"})
	writeJSON(t, filepath.Join(root, "packages", "b", "package.json"), map[string]any{"name": "b"})

	got, err := NewInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	byPath := packagesByPath(got.Packages)
	understood := byPath["packages/a"].Workspace && byPath["packages/b"].Workspace
	if !understood && got.Complete {
		t.Fatalf("extended glob was silently misinterpreted with Complete=true: %#v", got)
	}
}

func TestAuditNPMPositiveOverrideAfterNegationCannotSilentlyDisappear(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, filepath.Join(root, "package.json"), map[string]any{
		"name": "root", "private": true, "packageManager": "npm@12.0.1",
		"workspaces": []string{"packages/**", "!packages/b/**", "packages/b/a"},
	})
	writeJSON(t, filepath.Join(root, "packages", "b", "a", "package.json"), map[string]any{"name": "a"})

	got, err := NewInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !packagesByPath(got.Packages)["packages/b/a"].Workspace && got.Complete {
		t.Fatalf("npm positive override was silently converted to permanent exclusion: %#v", got)
	}
}

func TestAuditPNPMYAMLAnchorCannotSilentlyDisappear(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, filepath.Join(root, "package.json"), map[string]any{"name": "root", "private": true})
	writeFile(t, filepath.Join(root, "pnpm-workspace.yaml"), "packages:\n  - &workspace 'packages/*'\n")
	writeJSON(t, filepath.Join(root, "packages", "a", "package.json"), map[string]any{"name": "a"})

	got, err := NewInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	understood := packagesByPath(got.Packages)["packages/a"].Workspace
	if !understood && got.Complete {
		t.Fatalf("valid YAML anchor syntax was silently misinterpreted with Complete=true: %#v", got)
	}
}

func TestAuditWorkspacePatternWhitespaceCannotSilentlyDisappear(t *testing.T) {
	if filepath.Separator == '\\' {
		t.Skip("trailing-space path semantics are not portable to Windows")
	}
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, filepath.Join(root, "package.json"), map[string]any{
		"name": "root", "private": true, "workspaces": []string{" packages/a "},
	})
	writeJSON(t, filepath.Join(root, " packages", "a ", "package.json"), map[string]any{"name": "spaced"})

	got, err := NewInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	understood := packagesByPath(got.Packages)[" packages/a "].Workspace
	if !understood && got.Complete {
		t.Fatalf("workspace pattern/path whitespace was silently normalized away: %#v", got)
	}
}
