//go:build linux

package toolrunner

import (
	"os/exec"
	"syscall"
)

// placeInCgroup makes the child be created directly inside the cgroup v2 directory
// referenced by fd (clone3 CLONE_INTO_CGROUP), so the connect-logger attached to
// that cgroup captures the tool's connects race-free. Extends the SysProcAttr that
// configureProcessGroup already set (process-group kill); a no-op if fd is not set.
func placeInCgroup(cmd *exec.Cmd, fd int) {
	if fd <= 0 {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.UseCgroupFD = true
	cmd.SysProcAttr.CgroupFD = fd
}
