package ebpf

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ErrRuntimeSensorUnavailable means positive runtime reachability telemetry cannot be observed on this
// host. Callers must treat this as no runtime evidence, never as evidence that code did not execute.
var ErrRuntimeSensorUnavailable = errors.New("ebpf runtime reachability sensor unavailable")

const maxRuntimeSymbolProbes = 64

// RuntimeSymbolProbe identifies one exact file-backed function to observe with an entry uprobe. PID==0
// attaches host-wide; a positive PID scopes the probe to that process. This is only an observation
// target. Matching it to a package/finding belongs to #1061.
type RuntimeSymbolProbe struct {
	Path   string
	Symbol string
	PID    int
}

func (p RuntimeSymbolProbe) validate() (RuntimeSymbolProbe, error) {
	p.Path = filepath.Clean(strings.TrimSpace(p.Path))
	p.Symbol = strings.TrimSpace(p.Symbol)
	if p.Path == "." || p.Path == "" || !filepath.IsAbs(p.Path) {
		return RuntimeSymbolProbe{}, fmt.Errorf("%w: runtime symbol probe path must be absolute", shared.ErrValidation)
	}
	if p.Symbol == "" {
		return RuntimeSymbolProbe{}, fmt.Errorf("%w: runtime symbol probe requires a symbol", shared.ErrValidation)
	}
	if p.PID < 0 {
		return RuntimeSymbolProbe{}, fmt.Errorf("%w: runtime symbol probe has negative pid %d", shared.ErrValidation, p.PID)
	}
	return p, nil
}

func runtimeProbeKey(p RuntimeSymbolProbe) string {
	return fmt.Sprintf("%s\x00%s\x00%d", p.Path, p.Symbol, p.PID)
}
