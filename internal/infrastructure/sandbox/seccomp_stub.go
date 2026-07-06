//go:build !(linux && amd64)

package sandbox

import (
	"errors"
	"os"
)

// On platforms without a seccomp implementation (darwin dev, non-amd64 Linux), the sandbox
// is either unavailable already (no bwrap on darwin) or unsupported. seccompFile fails so
// NewRunner fails closed (F1: never run a "sandbox" that silently lacks seccomp).
var errSeccompUnsupported = errors.New("seccomp filtering unsupported on this platform")

func seccompFile() (*os.File, error) { return nil, errSeccompUnsupported }

const seccompSupported = false
