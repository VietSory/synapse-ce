//go:build unix

package toolrunner

import (
	"os/exec"
	"syscall"
)

// configureProcessGroup makes the tool a process-group leader (Setpgid) and replaces
// the default context-cancel (which kills only the direct child) with a kill of the
// entire group, so resolver/helper grandchildren spawned by recon tools die with the
// parent on a timeout or shutdown (F-1). The group id equals the child pid because it
// is the group leader; signalling the negative pid targets the whole group.
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Best-effort: ESRCH (already gone) is not an error worth surfacing.
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
			return err
		}
		return nil
	}
}
