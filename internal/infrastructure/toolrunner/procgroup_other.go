//go:build !unix

package toolrunner

import "os/exec"

// configureProcessGroup is a no-op on non-unix platforms: os/exec's default
// context-cancel (kill the direct child) is kept. Synapse targets unix (Linux
// servers, darwin dev); this stub only keeps the package building elsewhere.
func configureProcessGroup(_ *exec.Cmd) {}
