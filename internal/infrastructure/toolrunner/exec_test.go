package toolrunner

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func skipIfMissing(t *testing.T, bin string) {
	t.Helper()
	if _, err := exec.LookPath(bin); err != nil {
		t.Skipf("%s not on PATH", bin)
	}
}

func TestRunArgvCapturesStdout(t *testing.T) {
	skipIfMissing(t, "echo")
	res, err := NewExecRunner(time.Second, 1<<20).Run(context.Background(),
		ports.ToolSpec{Name: "echo", Args: []string{"hello", "world"}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "hello world" {
		t.Errorf("stdout = %q, want %q", got, "hello world")
	}
	if res.ExitCode != 0 || res.TimedOut || res.Truncated {
		t.Errorf("unexpected result %+v", res)
	}
}

func TestRunTimeoutKillsProcess(t *testing.T) {
	skipIfMissing(t, "sleep")
	start := time.Now()
	res, err := NewExecRunner(50*time.Millisecond, 1<<20).Run(context.Background(),
		ports.ToolSpec{Name: "sleep", Args: []string{"10"}})
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if !res.TimedOut {
		t.Error("TimedOut should be set")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("process was not killed promptly (took %s)", elapsed)
	}
}

func TestRunOutputCapTruncates(t *testing.T) {
	skipIfMissing(t, "head")
	res, err := NewExecRunner(5*time.Second, 1000).Run(context.Background(),
		ports.ToolSpec{Name: "head", Args: []string{"-c", "1000000", "/dev/zero"}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res.Truncated {
		t.Error("expected Truncated to be set")
	}
	if len(res.Stdout) > 1000 {
		t.Errorf("stdout exceeded the cap: %d bytes", len(res.Stdout))
	}
}

func TestRunStdinIsData(t *testing.T) {
	skipIfMissing(t, "cat")
	res, err := NewExecRunner(time.Second, 1<<20).Run(context.Background(),
		ports.ToolSpec{Name: "cat", Stdin: []byte("piped-in")})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if string(res.Stdout) != "piped-in" {
		t.Errorf("stdout = %q", res.Stdout)
	}
}

func TestRunNonZeroExitIsNotAnError(t *testing.T) {
	skipIfMissing(t, "false")
	res, err := NewExecRunner(time.Second, 1<<20).Run(context.Background(),
		ports.ToolSpec{Name: "false"})
	if err != nil {
		t.Fatalf("a non-zero exit must not be a Go error: %v", err)
	}
	if res.ExitCode == 0 {
		t.Error("expected a non-zero exit code")
	}
}

func TestRunMissingBinaryErrors(t *testing.T) {
	_, err := NewExecRunner(time.Second, 1<<20).Run(context.Background(),
		ports.ToolSpec{Name: "synapse-no-such-binary-xyz"})
	if err == nil {
		t.Fatal("expected an error for a missing binary")
	}
}
