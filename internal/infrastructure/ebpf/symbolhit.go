package ebpf

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ErrSymbolHitUnavailable means this host cannot produce positive runtime symbol-hit evidence.
// Callers must treat it as no evidence, never as proof that the symbol did not execute.
var ErrSymbolHitUnavailable = errors.New("ebpf runtime symbol-hit sensor unavailable")

// RuntimeSymbolProbe identifies one exact file-backed function to observe. PID==0 is host-wide;
// a positive PID scopes the uprobe to one process. Fan-out/package matching belongs to #1061.
type RuntimeSymbolProbe struct {
	Path   string
	Symbol string
	PID    int
}

func (p RuntimeSymbolProbe) validate() (RuntimeSymbolProbe, error) {
	p.Path = path.Clean(strings.TrimSpace(p.Path))
	p.Symbol = strings.TrimSpace(p.Symbol)
	if p.Path == "." || p.Path == "" || !strings.HasPrefix(p.Path, "/") {
		return RuntimeSymbolProbe{}, fmt.Errorf("%w: runtime symbol probe path must be an absolute Linux path", shared.ErrValidation)
	}
	if p.Symbol == "" {
		return RuntimeSymbolProbe{}, fmt.Errorf("%w: runtime symbol probe requires a symbol", shared.ErrValidation)
	}
	if p.PID < 0 {
		return RuntimeSymbolProbe{}, fmt.Errorf("%w: runtime symbol probe has negative pid %d", shared.ErrValidation, p.PID)
	}
	return p, nil
}
