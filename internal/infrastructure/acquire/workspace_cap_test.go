package acquire

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestWorkspaceCapConfigurable pins WithMaxWorkspaceBytes (wired from SYNAPSE_MAX_WORKSPACE_BYTES):
// a local target whose files exceed the configured cap is rejected, a raised cap accepts it, and a
// non-positive override leaves the 2 GiB default in force.
func TestWorkspaceCapConfigurable(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	// ~4 KiB of files in the workspace.
	if err := os.WriteFile(filepath.Join(dir, "data.bin"), make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	req := ports.AcquireRequest{Kind: ports.TargetLocal, Value: dir}

	t.Run("over the configured cap is rejected", func(t *testing.T) {
		_, err := New().WithMaxWorkspaceBytes(1024).Acquire(ctx, req)
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want ErrValidation (target exceeds cap), got %v", err)
		}
	})

	t.Run("under a raised cap is accepted", func(t *testing.T) {
		ws, err := New().WithMaxWorkspaceBytes(1<<20).Acquire(ctx, req)
		if err != nil {
			t.Fatalf("under-cap target should acquire: %v", err)
		}
		if ws == nil || ws.Dir != dir {
			t.Fatalf("unexpected workspace: %+v", ws)
		}
	})

	t.Run("non-positive override keeps the default cap", func(t *testing.T) {
		// 0 is ignored, so the 2 GiB MaxWorkspaceBytes default stands and a tiny dir passes.
		if _, err := New().WithMaxWorkspaceBytes(0).Acquire(ctx, req); err != nil {
			t.Fatalf("default cap should accept a tiny target: %v", err)
		}
	})
}
