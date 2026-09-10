//go:build !cgo

package astwalk

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
)

// JSFactsFor is unavailable in CGO-free builds because JavaScript/TypeScript grammars live only in
// the sandboxed synapse-ast sidecar. The provider maps ErrUnavailable to available=false.
func JSFactsFor(ctx context.Context, root string) (jsprogram.Document, error) {
	return jsprogram.Document{}, ErrUnavailable
}
