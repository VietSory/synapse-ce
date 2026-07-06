package syft_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/syft"
)

// TestSyftSandboxedMatchesDirect proves that running Syft inside the sandbox
// yields the SAME SBOM as a direct exec (the sandbox changes HOW it runs, not the
// output). Needs syft + bubblewrap on the host.
func TestSyftSandboxedMatchesDirect(t *testing.T) {
	if _, err := exec.LookPath("syft"); err != nil {
		t.Skip("syft not installed")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap not installed")
	}
	dir := t.TempDir()
	lock := `{"name":"t","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"t","version":"1.0.0"},"node_modules/lodash":{"version":"4.17.4","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.4.tgz","integrity":"sha1-x"}}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	direct, err := syft.New("syft").Generate(ctx, dir)
	if err != nil {
		t.Fatalf("direct syft: %v", err)
	}
	sb, err := sandbox.NewRunner(2*time.Minute, 16<<20, 512<<20, 256)
	if err != nil {
		t.Fatalf("sandbox: %v", err)
	}
	sandboxed, err := syft.New("syft").WithRunner(sb).Generate(ctx, dir)
	if err != nil {
		t.Fatalf("sandboxed syft: %v", err)
	}
	d, x := purlSet(direct.Raw), purlSet(sandboxed.Raw)
	if len(d) == 0 {
		t.Fatalf("direct SBOM has no components: %s", direct.Raw)
	}
	if !equalSorted(d, x) {
		t.Errorf("sandboxed SBOM differs from direct:\n direct=%v\n sandbox=%v", d, x)
	}
}
