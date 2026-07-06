package sca

import (
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestNormalizeLocalTarget pins the cross-OS local-path canonicalization: a local target is
// made absolute + cleaned so it matches scope (and acquires) the same way no matter how it was
// typed, while non-local kinds (git URL, archive, image) are left untouched.
func TestNormalizeLocalTarget(t *testing.T) {
	absProj, err := filepath.Abs("proj")
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	abs := func(p string) string {
		got, err := filepath.Abs(filepath.Clean(p))
		if err != nil {
			t.Fatalf("filepath.Abs(%q): %v", p, err)
		}
		return got
	}
	cases := []struct {
		name string
		in   ports.AcquireRequest
		want string
	}{
		{"trailing slash trimmed", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "/tmp/proj/"}, abs("/tmp/proj/")},
		{"dotdot collapsed", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "/tmp/a/../proj"}, abs("/tmp/proj")},
		{"dot segment + empty kind treated as local", ports.AcquireRequest{Value: "/tmp/proj/."}, abs("/tmp/proj/.")},
		{"dot-relative path made absolute", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "./proj"}, absProj},
		{"bare logical token left exact", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"}, "myrepo"},
		{"git url untouched", ports.AcquireRequest{Kind: ports.TargetGit, Value: "https://github.com/x/y"}, "https://github.com/x/y"},
		{"archive untouched", ports.AcquireRequest{Kind: ports.TargetArchive, Value: "/up//loads/a.zip"}, "/up//loads/a.zip"},
		{"image untouched", ports.AcquireRequest{Kind: ports.TargetImage, Value: "docker.io/library/nginx:latest"}, "docker.io/library/nginx:latest"},
		{"empty value untouched", ports.AcquireRequest{Kind: ports.TargetLocal, Value: ""}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeLocalTarget(tc.in).Value; got != tc.want {
				t.Errorf("normalizeLocalTarget(%q, kind=%q).Value = %q, want %q", tc.in.Value, tc.in.Kind, got, tc.want)
			}
		})
	}
}
