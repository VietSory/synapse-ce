package acquire

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// writeZip builds a.zip at a temp path from the given entries (name → content); a nil
// content with a name ending in "/" is a dir, and symlink entries are flagged.
func writeZip(t *testing.T, entries []zipEntry) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "a.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for _, e := range entries {
		hdr := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.symlink {
			hdr.SetMode(fs.ModeSymlink | 0o777)
		} else {
			hdr.SetMode(0o644)
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(e.content))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

type zipEntry struct {
	name    string
	content string
	symlink bool
}

func TestExtractZipNormal(t *testing.T) {
	src := writeZip(t, []zipEntry{{name: "go.mod", content: "module example.com/x\n"}, {name: "pkg/a.go", content: "package pkg"}})
	dest := t.TempDir()
	if err := extractZip(src, dest, MaxWorkspaceBytes); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "go.mod")); err != nil || string(b) != "module example.com/x\n" {
		t.Errorf("go.mod not extracted: %v %q", err, b)
	}
	if _, err := os.Stat(filepath.Join(dest, "pkg/a.go")); err != nil {
		t.Errorf("nested file not extracted: %v", err)
	}
}

func TestExtractZipRejectsZipSlip(t *testing.T) {
	src := writeZip(t, []zipEntry{{name: "../escape.txt", content: "pwned"}})
	dest := t.TempDir()
	if err := extractZip(src, dest, MaxWorkspaceBytes); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a zip-slip entry must be rejected, got %v", err)
	}
	// The file must not have escaped to the parent.
	if _, err := os.Stat(filepath.Join(filepath.Dir(dest), "escape.txt")); err == nil {
		t.Fatal("zip-slip wrote outside the workspace")
	}
}

func TestExtractZipSkipsSymlinks(t *testing.T) {
	src := writeZip(t, []zipEntry{
		{name: "real.txt", content: "ok"},
		{name: "evil-link", content: "/etc/passwd", symlink: true},
	})
	dest := t.TempDir()
	if err := extractZip(src, dest, MaxWorkspaceBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "evil-link")); err == nil {
		t.Error("a symlink entry must be skipped, not created")
	}
	if _, err := os.Stat(filepath.Join(dest, "real.txt")); err != nil {
		t.Error("the regular file should still extract")
	}
}

func writeTarGz(t *testing.T, hdrs []*tar.Header, bodies []string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "a.tar.gz")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for i, h := range hdrs {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if bodies[i] != "" {
			_, _ = tw.Write([]byte(bodies[i]))
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return p
}

func TestExtractTarGzNormalAndSkipsLinks(t *testing.T) {
	hdrs := []*tar.Header{
		{Name: "src/main.go", Typeflag: tar.TypeReg, Mode: 0o644, Size: 4},
		{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777},
	}
	src := writeTarGz(t, hdrs, []string{"main", ""})
	dest := t.TempDir()
	if err := extractTarGz(src, dest, MaxWorkspaceBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "src/main.go")); err != nil {
		t.Errorf("regular file not extracted: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "link")); err == nil {
		t.Error("a tar symlink must be skipped")
	}
}

func TestExtractTarGzRejectsTraversal(t *testing.T) {
	hdrs := []*tar.Header{{Name: "../../etc/cron.d/x", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1}}
	src := writeTarGz(t, hdrs, []string{"x"})
	if err := extractTarGz(src, t.TempDir(), MaxWorkspaceBytes); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("tar path traversal must be rejected, got %v", err)
	}
}

func TestExtractZipPerFileCap(t *testing.T) {
	dest := t.TempDir()
	// A buffer larger than the per-file cap; build a zip whose single entry exceeds it.
	big := bytes.Repeat([]byte("A"), int(maxArchiveFileBytes)+1024)
	p := filepath.Join(t.TempDir(), "big.zip")
	f, _ := os.Create(p)
	zw := zip.NewWriter(f)
	w, _ := zw.CreateHeader(&zip.FileHeader{Name: "big.bin", Method: zip.Store})
	_, _ = w.Write(big)
	_ = zw.Close()
	_ = f.Close()
	if err := extractZip(p, dest, MaxWorkspaceBytes); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an over-cap entry must be rejected, got %v", err)
	}
}

func TestAcquireArchiveRejectsUnsupported(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.rar")
	_ = os.WriteFile(p, []byte("not a real rar"), 0o644)
	if _, err := acquireArchive(p, MaxWorkspaceBytes); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unsupported archive type must be rejected, got %v", err)
	}
}
