package enry

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDetectAggregatesLanguages(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, "main.go", "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"hi\") }\n")
	mustWrite(t, dir, "app.py", "def add(a, b):\n    return a + b\n\n\nprint(add(1, 2))\n")

	langs, err := New().Detect(context.Background(), dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	seen := map[string]float64{}
	var sum float64
	for _, l := range langs {
		seen[l.Name] = l.Percent
		sum += l.Percent
	}
	if _, ok := seen["Go"]; !ok {
		t.Errorf("want Go in result, got %+v", langs)
	}
	if _, ok := seen["Python"]; !ok {
		t.Errorf("want Python in result, got %+v", langs)
	}
	if sum < 99.9 || sum > 100.1 {
		t.Errorf("percentages should sum to ~100, got %.4f", sum)
	}
}

func TestDetectSingleFile(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, "main.go", "package main\n\nfunc main() {}\n")

	langs, err := New().Detect(context.Background(), filepath.Join(dir, "main.go"))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(langs) != 1 || langs[0].Name != "Go" {
		t.Fatalf("want single Go result, got %+v", langs)
	}
}

func TestDetectEmptyResultIsNonNil(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, "config.yaml", "key: value\nlist:\n  - a\n  - b\n") // Data type → not counted

	langs, err := New().Detect(context.Background(), dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if langs == nil {
		t.Fatal("want non-nil empty slice, got nil")
	}
	if len(langs) != 0 {
		t.Fatalf("want empty result, got %+v", langs)
	}
}

func TestDetectHonorsCancellation(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, "main.go", "package main\n\nfunc main() {}\n")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().Detect(ctx, dir); err == nil {
		t.Fatal("want cancellation error, got nil")
	}
}

func TestDetectDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, "secret.go", "package secret\n")
	link := filepath.Join(dir, "link.go")
	if err := os.Symlink(filepath.Join(dir, "secret.go"), link); err != nil {
		t.Skipf("symlinks unsupported here: %v", err)
	}

	// Targeting the symlink directly must not be followed (arbitrary-file-read guard).
	langs, err := New().Detect(context.Background(), link)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(langs) != 0 {
		t.Fatalf("symlink target must not be followed, got %+v", langs)
	}
}

func TestDetectMissingPath(t *testing.T) {
	if _, err := New().Detect(context.Background(), filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("want error for missing path")
	}
}

func mustWrite(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
