//go:build !linux

package toolrunner

import "os/exec"

// placeInCgroup is a no-op off Linux (clone-into-cgroup is a Linux feature).
func placeInCgroup(_ *exec.Cmd, _ int) {}
