package ownsbom

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryGenerate(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "go.mod"), goModFixture)
	// A vendored copy whose manifest MUST be skipped (else its deps double-count / mis-scope).
	nested := filepath.Join(dir, "node_modules", "pkg")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(nested, "go.mod"), "module nested\n\nrequire github.com/should/skip v9.9.9\n")
	mustWrite(t, filepath.Join(dir, "README.md"), "# not a manifest")

	reg, err := New(GoMod{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	doc, err := reg.Generate(context.Background(), dir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if doc.Source != "ownsbom" || doc.GeneratorVersion != ownsbomVersion {
		t.Errorf("provenance = %q/%q, want ownsbom/%s", doc.Source, doc.GeneratorVersion, ownsbomVersion)
	}
	if len(doc.Components) != 3 {
		t.Fatalf("want 3 components from the top go.mod, got %d: %+v", len(doc.Components), doc.Components)
	}
	for _, c := range doc.Components {
		if c.Name == "github.com/should/skip" {
			t.Error("node_modules manifest must be skipped (dependency-cache dir)")
		}
	}
}

func TestRegistryDuplicateMarker(t *testing.T) {
	if _, err := New(GoMod{}, GoMod{}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("two parsers claiming the same marker must fail validation, got %v", err)
	}
	if _, err := New(nil); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("nil parser must fail validation, got %v", err)
	}
}

func TestRegistryNonDirTarget(t *testing.T) {
	reg, err := New(GoMod{})
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "go.mod")
	mustWrite(t, f, goModFixture)
	if _, err := reg.Generate(context.Background(), f); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("a file (non-dir) target must fail validation, got %v", err)
	}
}
